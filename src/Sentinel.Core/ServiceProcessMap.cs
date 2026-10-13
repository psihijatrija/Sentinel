using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Maps Windows service short names <-> hosting process IDs (including shared svchost).
    /// Enables privacy/outbound attribution without killing shared hosts.
    /// v1.9.9 - observe-first; map is read-only attribution.
    /// </summary>
    public sealed class ServiceProcessMap
    {
        private readonly ILogger<ServiceProcessMap>? _logger;
        private readonly object _refreshLock = new();

        private ConcurrentDictionary<string, int> _serviceToPid =
            new(StringComparer.OrdinalIgnoreCase);
        private ConcurrentDictionary<int, List<string>> _pidToServices = new();
        private ConcurrentDictionary<string, string> _serviceDisplayNames =
            new(StringComparer.OrdinalIgnoreCase);
        private DateTimeOffset _lastRefreshUtc = DateTimeOffset.MinValue;

        public ServiceProcessMap(ILogger<ServiceProcessMap>? logger = null)
        {
            _logger = logger;
        }

        public DateTimeOffset LastRefreshUtc => _lastRefreshUtc;

        /// <summary>
        /// Refresh maps from Win32_Service. Safe to call often; skips if last refresh
        /// was within <paramref name="minInterval"/> (default 10s).
        /// </summary>
        public void Refresh(TimeSpan? minInterval = null, CancellationToken ct = default)
        {
            var min = minInterval ?? TimeSpan.FromSeconds(10);
            if (DateTimeOffset.UtcNow - _lastRefreshUtc < min && _serviceToPid.Count > 0)
                return;

            lock (_refreshLock)
            {
                if (DateTimeOffset.UtcNow - _lastRefreshUtc < min && _serviceToPid.Count > 0)
                    return;

                try
                {
                    ct.ThrowIfCancellationRequested();
                    var serviceToPid = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                    var pidToServices = new ConcurrentDictionary<int, List<string>>();
                    var displayNames = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                    using var searcher = new ManagementObjectSearcher(
                        "SELECT Name, ProcessId, State, DisplayName FROM Win32_Service");
                    using var results = searcher.Get();

                    foreach (ManagementBaseObject obj in results)
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var mo = (ManagementObject)obj;
                            var name = mo["Name"] as string;
                            if (string.IsNullOrWhiteSpace(name)) continue;

                            var display = mo["DisplayName"] as string ?? name;
                            displayNames[name!] = display!;

                            var state = mo["State"] as string;
                            if (!string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase))
                                continue;

                            var pidObj = mo["ProcessId"];
                            if (pidObj == null) continue;
                            int pid = Convert.ToInt32(pidObj);
                            if (pid <= 0) continue;

                            serviceToPid[name!] = pid;
                            var list = pidToServices.GetOrAdd(pid, _ => new List<string>());
                            lock (list)
                            {
                                if (!list.Any(s => string.Equals(s, name, StringComparison.OrdinalIgnoreCase)))
                                    list.Add(name!);
                            }
                        }
                        catch
                        {
                            // Per-service failure must not abort full refresh.
                        }
                    }

                    _serviceToPid = serviceToPid;
                    _pidToServices = pidToServices;
                    _serviceDisplayNames = displayNames;
                    _lastRefreshUtc = DateTimeOffset.UtcNow;
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    _logger?.LogDebug(ex, "[ServiceProcessMap] Refresh failed");
                }
            }
        }

        public bool TryGetPidForService(string serviceName, out int pid)
        {
            pid = 0;
            if (string.IsNullOrWhiteSpace(serviceName)) return false;
            return _serviceToPid.TryGetValue(serviceName.Trim(), out pid) && pid > 0;
        }

        public bool TryGetServicesForPid(int pid, out IReadOnlyList<string> serviceNames)
        {
            serviceNames = Array.Empty<string>();
            if (pid <= 0) return false;
            if (!_pidToServices.TryGetValue(pid, out var list) || list == null || list.Count == 0)
                return false;

            lock (list)
            {
                serviceNames = list.ToArray();
            }
            return serviceNames.Count > 0;
        }

        public string GetDisplayName(string serviceName)
        {
            if (string.IsNullOrWhiteSpace(serviceName)) return serviceName ?? "";
            return _serviceDisplayNames.TryGetValue(serviceName, out var d) ? d : serviceName;
        }

        public bool IsServiceRunning(string serviceName)
            => TryGetPidForService(serviceName, out _);

        public int MappedServiceCount => _serviceToPid.Count;
    }
}
