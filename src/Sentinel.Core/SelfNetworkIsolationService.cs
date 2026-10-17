using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public sealed class WindowsSelfNetworkFirewall : ISelfNetworkFirewall
    {
        public void UpsertAndVerify(SelfNetworkBlockRule rule)
        {
            object? policyObject = null;
            object? rulesObject = null;
            object? ruleObject = null;
            try
            {
                policyObject = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!);
                dynamic policy = policyObject!;
                rulesObject = policy.Rules;
                dynamic rules = rulesObject!;
                // Add replaces the fixed rule identifier using a fresh object. This drops stale
                // service/port/interface restrictions that could otherwise weaken an existing rule.
                ruleObject = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true)!);
                dynamic native = ruleObject!;
                native.Name = rule.Name;
                native.Description = "Blocks Sentinel non-loopback traffic. Local dashboard and IPC remain available.";
                native.Grouping = SelfNetworkBlockRule.Group;
                native.ApplicationName = rule.ApplicationPath;
                native.Protocol = 256; // NET_FW_IP_PROTOCOL_ANY
                native.LocalAddresses = "*";
                native.RemoteAddresses = SelfNetworkBlockRule.RemoteAddresses;
                native.Direction = rule.Direction;
                native.Profiles = 7; // Domain, Private, Public
                native.Action = 0; // NET_FW_ACTION_BLOCK
                native.InterfaceTypes = "All";
                native.Enabled = true;
                rules.Add(native);
                Release(ruleObject);
                ruleObject = rules.Item(rule.Name);
                native = ruleObject;
                if (!(bool)native.Enabled || (int)native.Action != 0 || (int)native.Direction != rule.Direction
                    || (int)native.Profiles != 7 || (int)native.Protocol != 256
                    || !string.Equals((string)native.ApplicationName, rule.ApplicationPath, StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(((string)native.RemoteAddresses).Replace(" ", ""), SelfNetworkBlockRule.RemoteAddresses, StringComparison.OrdinalIgnoreCase)
                    || !string.Equals((string)native.LocalAddresses, "*", StringComparison.Ordinal)
                    || !string.IsNullOrEmpty((string)native.ServiceName))
                    throw new InvalidOperationException("Self isolation rule verification failed: " + rule.Name);
            }
            finally
            {
                Release(ruleObject); Release(rulesObject); Release(policyObject);
            }
        }

        public void VerifyEnabled()
        {
            object? policyObject = null;
            try
            {
                policyObject = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!);
                dynamic policy = policyObject!;
                foreach (var profile in new[] { 1, 2, 4 })
                    if (!(bool)policy.FirewallEnabled[profile])
                        throw new InvalidOperationException("Windows Firewall profile " + profile + " is disabled; self isolation is not enforced.");
            }
            finally { Release(policyObject); }
        }

        public void Remove(string name)
        {
            object? policyObject = null;
            object? rulesObject = null;
            try
            {
                policyObject = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!);
                dynamic policy = policyObject!;
                rulesObject = policy.Rules;
                dynamic rules = rulesObject!;
                try { rules.Remove(name); }
                catch (COMException ex) when (ex.HResult == unchecked((int)0x80070002)) { }
            }
            finally { Release(rulesObject); Release(policyObject); }
        }

        private static void Release(object? value)
        {
            if (value != null && Marshal.IsComObject(value)) Marshal.FinalReleaseComObject(value);
        }
    }

    public sealed class SelfNetworkIsolationService : BackgroundService
    {
        private readonly SelfNetworkIsolation _isolation;
        private readonly ILogger<SelfNetworkIsolationService> _logger;
        public SelfNetworkIsolationService(ISelfNetworkFirewall firewall, ILogger<SelfNetworkIsolationService> logger)
        {
            _isolation = new SelfNetworkIsolation(firewall, AppDomain.CurrentDomain.BaseDirectory);
            _logger = logger;
        }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    _isolation.Apply();
                    _logger.LogInformation("[SelfNetworkIsolation] Non-loopback block rules verified for Sentinel processes");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[SelfNetworkIsolation] Firewall isolation could not be enforced; offline detection continues. Retrying in 60 seconds");
                }
                try { await Task.Delay(TimeSpan.FromSeconds(60), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            }
        }
    }
}
