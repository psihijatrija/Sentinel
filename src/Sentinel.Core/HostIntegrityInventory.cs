using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Sentinel.Core
{
    public interface IHostIntegrityInventory
    {
        HostIntegritySnapshot Capture();
    }

    /// <summary>Read-only observations. Network context IDs and certificate presence
    /// never authorize trust, exclusions, or remediation.</summary>
    public sealed class HostIntegrityInventory : IHostIntegrityInventory
    {
        public HostIntegritySnapshot Capture()
        {
            var snapshot = new HostIntegritySnapshot { ObservedUtc = DateTimeOffset.UtcNow };
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                var ip = adapter.GetIPProperties();
                // Hash identifiers/configuration locally: no adapter names, MACs or
                // plaintext DNS/gateway addresses need to enter the history.
                var state = adapter.OperationalStatus + "|" +
                    string.Join(",", ip.GatewayAddresses.Select(g => g.Address.ToString()).OrderBy(g => g, StringComparer.Ordinal)) + "|" +
                    string.Join(",", ip.DnsAddresses.Select(d => d.ToString()).OrderBy(d => d, StringComparer.Ordinal));
                snapshot.Network[Digest(adapter.Id)] = Digest(state);
            }
            snapshot.NetworkContextId = Digest(string.Join(";", snapshot.Network.OrderBy(k => k.Key, StringComparer.Ordinal)
                .Select(k => k.Key + "=" + k.Value)));
            foreach (var location in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
            {
                using var store = new X509Store(StoreName.Root, location);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                foreach (var cert in store.Certificates)
                {
                    using (cert) snapshot.RootCertificates[location + ":" + Digest(cert.RawData)] = "Present";
                }
            }
            return snapshot;
        }

        private static string Digest(string text) => Digest(Encoding.UTF8.GetBytes(text));
        private static string Digest(byte[] bytes)
        {
            using var sha = SHA256.Create();
            return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
        }
    }

    public sealed class HostIntegritySnapshot
    {
        public int SchemaVersion { get; set; } = 1;
        public DateTimeOffset ObservedUtc { get; set; }
        public string NetworkContextId { get; set; } = "";
        public Dictionary<string, DateTimeOffset> ObservedContexts { get; set; } = new(StringComparer.Ordinal);
        public Dictionary<string, string> Network { get; set; } = new(StringComparer.Ordinal);
        public Dictionary<string, string> RootCertificates { get; set; } = new(StringComparer.Ordinal);
    }

    public sealed class HostIntegrityHistory
    {
        private readonly string _path;
        private bool _loadFailed;
        public HostIntegrityHistory(string? customDirectory = null)
        {
            var directory = customDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Sentinel", "baseline");
            Directory.CreateDirectory(directory);
            if (customDirectory == null) SecureCacheStore.TryLockDirectoryAcl(directory);
            _path = Path.Combine(directory, "host_integrity.json");
        }

        public HostIntegritySnapshot? Load()
        {
            if (!File.Exists(_path)) return null;
            try
            {
                using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (stream.Length > 20 * 1024 * 1024) throw new InvalidDataException("Integrity observation baseline exceeds 20 MiB.");
                var snapshot = JsonSerializer.Deserialize<HostIntegritySnapshot>(stream);
                if (snapshot == null || snapshot.SchemaVersion != 1 || snapshot.Network == null || snapshot.RootCertificates == null || snapshot.ObservedContexts == null)
                    throw new InvalidDataException("Unsupported or corrupt integrity observation baseline.");
                return snapshot;
            }
            catch
            {
                _loadFailed = true;
                throw; // Monitor logs degradation and preserves the unreadable baseline.
            }
        }

        public void Save(HostIntegritySnapshot snapshot)
        {
            if (_loadFailed) throw new InvalidDataException("Unreadable integrity history retained; automatic replacement refused.");
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(snapshot));
            var temp = _path + ".tmp";
            using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.Read | FileShare.Delete))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(flushToDisk: true);
            }
            if (File.Exists(_path)) File.Replace(temp, _path, null);
            else File.Move(temp, _path);
        }

        public static IReadOnlyList<IntegrityObservation> Compare(HostIntegritySnapshot? previous, HostIntegritySnapshot current)
        {
            var observations = new List<IntegrityObservation>();
            bool contextPreviouslyObserved = previous != null && (previous.NetworkContextId == current.NetworkContextId ||
                previous.ObservedContexts.ContainsKey(current.NetworkContextId));
            if (previous != null)
            {
                foreach (var context in previous.ObservedContexts) current.ObservedContexts[context.Key] = context.Value;
                if (!string.IsNullOrEmpty(previous.NetworkContextId) && !current.ObservedContexts.ContainsKey(previous.NetworkContextId))
                    current.ObservedContexts[previous.NetworkContextId] = previous.ObservedUtc;
            }
            current.ObservedContexts[current.NetworkContextId] = current.ObservedUtc;
            // Bounded observation history. Previously seen never means trusted.
            foreach (var old in current.ObservedContexts.OrderByDescending(k => k.Value).ThenBy(k => k.Key, StringComparer.Ordinal).Skip(64).ToList())
                current.ObservedContexts.Remove(old.Key);
            CompareScope("Network", previous?.Network, current.Network);
            CompareScope("RootCertificate", previous?.RootCertificates, current.RootCertificates);
            return observations;

            void CompareScope(string scope, Dictionary<string, string>? oldValues, Dictionary<string, string> newValues)
            {
                foreach (var key in newValues.Keys.Union(oldValues?.Keys ?? Enumerable.Empty<string>()).OrderBy(k => k, StringComparer.Ordinal))
                {
                    string? oldValue = null;
                    oldValues?.TryGetValue(key, out oldValue);
                    newValues.TryGetValue(key, out var newValue);
                    if (oldValue == newValue) continue;
                    observations.Add(new IntegrityObservation
                    {
                        Scope = scope, ObjectId = key, ObservedUtc = current.ObservedUtc,
                        PreviousObservationUtc = previous?.ObservedUtc, Previous = oldValue, Current = newValue,
                        Change = previous == null ? "InitialObservation" : oldValue == null ? "Added" : newValue == null ? "Removed" : "Changed",
                        NetworkContextId = current.NetworkContextId,
                        ContextChanged = previous != null && current.NetworkContextId != previous.NetworkContextId,
                        ContextPreviouslyObserved = contextPreviouslyObserved
                    });
                }
            }
        }
    }

    public sealed class IntegrityObservation
    {
        public string Scope { get; set; } = "";
        public string ObjectId { get; set; } = "";
        public DateTimeOffset ObservedUtc { get; set; }
        public DateTimeOffset? PreviousObservationUtc { get; set; }
        public string Change { get; set; } = "";
        public string? Previous { get; set; }
        public string? Current { get; set; }
        public string NetworkContextId { get; set; } = "";
        public bool ContextChanged { get; set; }
        public bool ContextPreviouslyObserved { get; set; }
        public bool GrantsTrust => false;
        public string Attribution { get; set; } = "Unknown: observation does not establish installer, actor or exact change time";
    }
}
