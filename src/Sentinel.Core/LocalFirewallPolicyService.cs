using System;
using System.Management;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public sealed class FirewallPolicyStatus
    {
        private string _json = "{\"PolicyCompliant\":false,\"Status\":\"not_verified\"}";
        private long _checkedUtcTicks;
        public string Json
        {
            get
            {
                var checkedAt = Interlocked.Read(ref _checkedUtcTicks);
                if (checkedAt > 0 && DateTime.UtcNow.Ticks - checkedAt > TimeSpan.FromMinutes(3).Ticks)
                    return "{\"PolicyCompliant\":false,\"Status\":\"verification_stale\"}";
                return Volatile.Read(ref _json);
            }
        }
        public void Update(string json)
        {
            Interlocked.Exchange(ref _json, json);
            Interlocked.Exchange(ref _checkedUtcTicks, DateTime.UtcNow.Ticks);
        }
    }

    /// <summary>Reconciles inbound defaults and reports effective/domain policy, never writing domain GPOs.</summary>
    public sealed class LocalFirewallPolicyService : BackgroundService
    {
        private readonly IWindowsFirewallPolicyBridge _bridge;
        private readonly FirewallPolicyStatus _status;
        private readonly ILogger<LocalFirewallPolicyService> _logger;
        private readonly SemaphoreSlim _changed = new(0, 1);
        public LocalFirewallPolicyService(IWindowsFirewallPolicyBridge bridge, FirewallPolicyStatus status,
            ILogger<LocalFirewallPolicyService> logger)
        { _bridge = bridge; _status = status; _logger = logger; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            using var local = Watch(@"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy");
            using var group = Watch(@"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall");
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var json = await _bridge.RunAsync("Apply", ct).ConfigureAwait(false);
                    _status.Update(json);
                    using var result = JsonDocument.Parse(json);
                    var root = result.RootElement;
                    if (!root.TryGetProperty("PolicyCompliant", out var compliant) || compliant.ValueKind != JsonValueKind.True)
                        _logger.LogError("[FirewallPolicy] Effective firewall policy has conflicts: {Result}", json);
                    else
                        _logger.LogInformation("[FirewallPolicy] Effective self-blocks and inbound baseline verified: {Result}", json);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex)
                {
                    _status.Update(JsonSerializer.Serialize(new { PolicyCompliant = false, Status = "verification_failed", Error = ex.Message }));
                    _logger.LogError(ex, "[FirewallPolicy] Policy reconciliation failed; protection is not verified. Retrying");
                }
                try
                {
                    await _changed.WaitAsync(TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
                    // Coalesce registry notifications from a Windows update / policy refresh.
                    await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                    while (_changed.Wait(0)) { }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            }
        }

        private ManagementEventWatcher? Watch(string path)
        {
            ManagementEventWatcher? watcher = null;
            try
            {
                watcher = new ManagementEventWatcher(new ManagementScope(@"\\.\root\default"), new WqlEventQuery(
                    "SELECT * FROM RegistryTreeChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE' AND RootPath='" + path + "'"));
                watcher.EventArrived += (_, __) => { try { _changed.Release(); } catch (SemaphoreFullException) { } };
                watcher.Start();
                return watcher;
            }
            catch (Exception ex)
            {
                watcher?.Dispose();
                _logger.LogWarning(ex, "[FirewallPolicy] Registry notifications unavailable; polling remains active every 15 seconds");
                return null;
            }
        }
    }
}
