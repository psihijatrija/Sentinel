using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace Sentinel.Core
{
    public interface IFirewallIsolationStore
    {
        IReadOnlyList<FirewallIsolationRule> Find(string name);
        void Add(FirewallIsolationRule rule);
        void Remove(string name);
    }

    public sealed class FirewallIsolationRule
    {
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string RemoteAddress { get; set; } = "";
        public int Direction { get; set; }
        public bool Enabled { get; set; } = true;
        public int Action { get; set; }
        public int Profiles { get; set; } = int.MaxValue;
        public int Protocol { get; set; } = 256;
        public string Application { get; set; } = "";
        public string Service { get; set; } = "";
        public string LocalAddresses { get; set; } = "*";
        public string LocalPorts { get; set; } = "*";
        public string RemotePorts { get; set; } = "*";
        public string InterfaceTypes { get; set; } = "All";
        public string Grouping { get; set; } = "";
        public bool EdgeTraversal { get; set; }
        public string[] Interfaces { get; set; } = Array.Empty<string>();
    }

    public sealed class FirewallIsolationRecord
    {
        public int SchemaVersion { get; set; } = 1;
        public string Id { get; set; } = "";
        public string TargetIp { get; set; } = "";
        public string State { get; set; } = "Prepared";
        public string Authorization { get; set; } = "";
        public DateTime CreatedUtc { get; set; }
        // Unique names mean the before-state must be absence; never overwrite an existing rule.
        public bool RulesExistedBefore { get; set; }
        public List<FirewallIsolationRule> Rules { get; set; } = new();
        public string? Error { get; set; }
        public string RecoveryScope { get; set; } = "Explicit rollback of these firewall rules only; DNS/ARP cache flushes and process termination cannot be undone";
    }

    /// <summary>Write-ahead isolation of one IP. Recovery is explicit, never action replay on startup.</summary>
    public sealed class FirewallIsolationTransaction
    {
        private readonly IFirewallIsolationStore _store;
        private readonly string _directory;
        private readonly object _gate = new();
        private readonly Dictionary<string, FirewallIsolationRecord> _activeByTarget = new(StringComparer.Ordinal);
        private bool _indexLoaded;
        private int _recordCount;
        private const int MaximumRecords = 4096;
        public FirewallIsolationTransaction(IFirewallIsolationStore store, string directory)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _directory = Path.GetFullPath(directory ?? throw new ArgumentNullException(nameof(directory)));
        }

        public FirewallIsolationRecord Apply(string targetIp, string authorization, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(authorization) || authorization.Length > 2048)
                throw new ArgumentException("A bounded authorization reference is required.", nameof(authorization));
            string target = CanonicalTarget(targetIp);
            lock (_gate)
            {
                ct.ThrowIfCancellationRequested();
                EnsureDirectory();
                if (!_indexLoaded)
                {
                    var files = Directory.EnumerateFiles(_directory, "*.firewall.json").Take(MaximumRecords + 1).ToList();
                    if (files.Count > MaximumRecords) throw new IOException("Recovery history limit exceeded; review and archive completed transactions.");
                    foreach (var previous in files.Select(Read).OrderBy(r => r.CreatedUtc).ThenBy(r => r.Id, StringComparer.Ordinal))
                        if (previous.State == "Verified") _activeByTarget[previous.TargetIp] = previous;
                    _recordCount = files.Count;
                    _indexLoaded = true;
                }
                if (_activeByTarget.TryGetValue(target, out var active))
                {
                    active = Read(JournalPath(active.Id));
                    if (active.State == "Verified")
                    {
                        if (active.Rules.All(r => _store.Find(r.Name).Count == 0)) _activeByTarget.Remove(target);
                        else { foreach (var rule in active.Rules) RequireMatching(rule); return active; }
                    }
                    else _activeByTarget.Remove(target);
                }
                if (_recordCount >= MaximumRecords) throw new IOException("Recovery history is full; review and archive completed transactions before adding rules.");
                var record = new FirewallIsolationRecord
                {
                    Id = Guid.NewGuid().ToString("N"), TargetIp = target,
                    Authorization = authorization, CreatedUtc = DateTime.UtcNow
                };
                record.Rules = IntendedRules(record.Id, target);
                foreach (var rule in record.Rules)
                    if (_store.Find(rule.Name).Count != 0) throw new InvalidOperationException("Isolation rule name already exists; nothing was changed.");
                EnsureDirectory();
                string path = JournalPath(record.Id);
                if (File.Exists(path)) throw new IOException("Isolation journal already exists.");
                Write(path, record); // No host mutation is allowed before durable Prepared state.
                _recordCount++;
                try
                {
                    record.State = "Applying";
                    Write(path, record);
                    foreach (var rule in record.Rules)
                    {
                        ct.ThrowIfCancellationRequested();
                        if (_store.Find(rule.Name).Count != 0) throw new InvalidOperationException("Isolation rule appeared during preparation.");
                        _store.Add(rule);
                        RequireMatching(rule);
                    }
                    record.State = "Applied";
                    Write(path, record);
                    foreach (var rule in record.Rules) RequireMatching(rule);
                    record.State = "Verified";
                    Write(path, record);
                    _activeByTarget[target] = record;
                    return record;
                }
                catch (Exception ex)
                {
                    record.State = "Failed";
                    record.Error = ex.GetType().Name;
                    Write(path, record); // Retain partial rules and before-state for explicit review.
                    if (ex is OperationCanceledException) throw;
                    return record;
                }
            }
        }

        public FirewallIsolationRecord Inspect(string journalPath)
        {
            lock (_gate) return Read(journalPath);
        }

        /// <summary>Explicit operator request. Only absent or unchanged transaction-owned rules are eligible.</summary>
        public FirewallIsolationRecord Rollback(string journalPath, CancellationToken ct = default)
        {
            lock (_gate)
            {
                var record = Read(journalPath);
                ct.ThrowIfCancellationRequested();
                // Preflight all names before deleting any, including interrupted application/rollback.
                foreach (var rule in record.Rules) RequireAbsentOrMatching(rule);
                record.State = "RollbackPrepared";
                record.Error = null;
                Write(journalPath, record);
                try
                {
                    record.State = "RollingBack";
                    Write(journalPath, record);
                    foreach (var rule in record.Rules)
                    {
                        ct.ThrowIfCancellationRequested();
                        bool exists = RequireAbsentOrMatching(rule);
                        if (!exists) continue;
                        _store.Remove(rule.Name);
                        if (_store.Find(rule.Name).Count != 0) throw new IOException("Firewall rule removal was not verified.");
                    }
                    record.State = "RolledBack";
                    Write(journalPath, record);
                    if (_activeByTarget.TryGetValue(record.TargetIp, out var active) && active.Id == record.Id)
                        _activeByTarget.Remove(record.TargetIp);
                    return record;
                }
                catch (Exception ex)
                {
                    record.State = "RollbackFailed";
                    record.Error = ex.GetType().Name;
                    Write(journalPath, record);
                    if (ex is OperationCanceledException) throw;
                    return record;
                }
            }
        }

        private void RequireMatching(FirewallIsolationRule rule)
        {
            if (!RequireAbsentOrMatching(rule)) throw new IOException("Firewall rule missing after application.");
        }
        private bool RequireAbsentOrMatching(FirewallIsolationRule rule)
        {
            var found = _store.Find(rule.Name);
            if (found.Count == 0) return false;
            if (found.Count != 1 || !SameRule(found[0], rule))
                throw new InvalidOperationException("Firewall rule was changed or duplicated; manual review required.");
            return true;
        }

        internal static bool SameRule(FirewallIsolationRule a, FirewallIsolationRule b) =>
            a.Name == b.Name && a.Description == b.Description && a.RemoteAddress == b.RemoteAddress &&
            a.Direction == b.Direction && a.Action == b.Action && a.Enabled == b.Enabled &&
            a.Profiles == b.Profiles && a.Protocol == b.Protocol && a.Application == b.Application &&
            a.Service == b.Service && a.LocalAddresses == b.LocalAddresses && a.LocalPorts == b.LocalPorts &&
            a.RemotePorts == b.RemotePorts && a.InterfaceTypes == b.InterfaceTypes && a.Grouping == b.Grouping && a.EdgeTraversal == b.EdgeTraversal &&
            a.Interfaces != null && b.Interfaces != null && a.Interfaces.SequenceEqual(b.Interfaces);

        private static List<FirewallIsolationRule> IntendedRules(string id, string target) => new[] { 1, 2 }.Select(direction =>
            new FirewallIsolationRule { Name = "Sentinel-Isolation-" + id + (direction == 1 ? "-IN" : "-OUT"),
                Description = "Sentinel isolation transaction " + id, RemoteAddress = target, Direction = direction }).ToList();

        private FirewallIsolationRecord Read(string path)
        {
            path = Path.GetFullPath(path);
            RequireLocalPath(path);
            if (!string.Equals(Path.GetDirectoryName(path), _directory, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Isolation journal must be in the configured recovery directory.");
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (file.Length > 65536) throw new InvalidDataException("Isolation journal exceeds 64 KiB.");
            using var reader = new StreamReader(file);
            var chars = new char[65537];
            int length = 0, read;
            while (length < chars.Length && (read = reader.Read(chars, length, chars.Length - length)) > 0) length += read;
            if (length == chars.Length) throw new InvalidDataException("Isolation journal exceeds 64 KiB.");
            var record = JsonSerializer.Deserialize<FirewallIsolationRecord>(new string(chars, 0, length))
                ?? throw new InvalidDataException("Missing isolation journal.");
            if (record.SchemaVersion != 1 || !Guid.TryParseExact(record.Id, "N", out _) || record.RulesExistedBefore ||
                record.CreatedUtc.Kind != DateTimeKind.Utc || string.IsNullOrWhiteSpace(record.Authorization) || record.Authorization.Length > 2048 ||
                Path.GetFileName(path) != record.Id + ".firewall.json" ||
                !new[] { "Prepared", "Applying", "Applied", "Verified", "Failed", "RollbackPrepared", "RollingBack", "RolledBack", "RollbackFailed" }.Contains(record.State))
                throw new InvalidDataException("Invalid or unsupported isolation journal.");
            string target = CanonicalTarget(record.TargetIp);
            var intended = IntendedRules(record.Id, target);
            if (target != record.TargetIp || record.Rules == null || record.Rules.Count != 2 ||
                !record.Rules.Zip(intended, (a, b) => a != null && SameRule(a, b)).All(matches => matches))
                throw new InvalidDataException("Isolation journal does not describe the expected transaction-owned rules.");
            return record;
        }

        private string JournalPath(string id) => Path.Combine(_directory, id + ".firewall.json");
        private void EnsureDirectory() { RequireLocalPath(_directory); Directory.CreateDirectory(_directory); RequireLocalPath(_directory); }
        private static void RequireLocalPath(string path)
        {
            if (!Path.IsPathRooted(path) || path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
                throw new InvalidDataException("Recovery paths must be absolute and local.");
            for (var current = path; !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
                if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException("Linked recovery paths require manual review.");
        }
        private static void Write(string path, FirewallIsolationRecord record)
        {
            RequireLocalPath(path);
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record));
            if (bytes.Length > 65536) throw new InvalidDataException("Isolation journal exceeds 64 KiB.");
            string temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.Read | FileShare.Delete))
            { output.Write(bytes, 0, bytes.Length); output.Flush(true); }
            if (File.Exists(path)) File.Replace(temp, path, null); else File.Move(temp, path);
        }
        internal static string CanonicalTarget(string value)
        {
            if (!IPAddress.TryParse(value, out var ip)) throw new ArgumentException("Invalid isolation IP.");
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            var bytes = ip.GetAddressBytes();
            bool local = IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) ||
                ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast;
            if (bytes.Length == 4)
                local |= bytes[0] == 0 || bytes[0] == 10 || bytes[0] == 127 || bytes[0] >= 224 ||
                    (bytes[0] == 169 && bytes[1] == 254) || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                    (bytes[0] == 192 && bytes[1] == 168) || (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127);
            else local |= (bytes[0] & 0xfe) == 0xfc;
            if (local) throw new ArgumentException("Local, private, multicast and unspecified isolation targets are refused.");
            return ip.ToString();
        }
    }
}
