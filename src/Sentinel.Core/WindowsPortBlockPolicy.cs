using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    internal sealed class PortBlockSpec
    {
        internal int Port { get; }
        internal int Protocol { get; }
        internal int Direction { get; }
        internal string Name => "Sentinel-PortBlock-" + Protocol + "-" + Direction + "-" + Port;
        internal PortBlockSpec(int port, int protocol, int direction)
        { Port = port; Protocol = protocol; Direction = direction; }
    }

    internal sealed class PortBlockInspection
    {
        internal bool Verified { get; set; }
        internal string Detail { get; set; } = "Configuration unavailable; packet enforcement is not verified.";
    }

    internal static class WindowsPortBlockPolicy
    {
        // Modern Windows Firewall supports these block filters without the legacy
        // `netsh ipsec static` extension. Names and ports come only from compiled policy.
        internal static PortBlockInspection Inspect(IEnumerable<PortBlockSpec> expected, bool apply)
        {
            object? policyObject = null, rulesObject = null;
            try
            {
                var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType == null) return new PortBlockInspection();
                policyObject = Activator.CreateInstance(policyType);
                if (policyObject == null) return new PortBlockInspection();
                dynamic policy = policyObject;
                rulesObject = policy.Rules;
                dynamic rules = rulesObject;
                int missing = 0;
                foreach (var spec in expected)
                {
                    object? ruleObject = null;
                    try
                    {
                        try { ruleObject = rules.Item(spec.Name); }
                        catch (COMException ex) when ((uint)ex.HResult == 0x80070002)
                        { Debug.WriteLine("[PortHardening] Owned rule absent: " + spec.Name); }
                        bool existed = ruleObject != null;
                        if (apply && ruleObject != null)
                        {
                            dynamic current = ruleObject;
                            if (Matches(spec, (bool)current.Enabled, (int)current.Action, (int)current.Protocol,
                                (int)current.Direction, (int)current.Profiles, (string)current.LocalPorts,
                                (string)current.RemotePorts, (string)current.ApplicationName, (string)current.ServiceName,
                                (string)current.LocalAddresses, (string)current.RemoteAddresses, (string)current.InterfaceTypes,
                                UnscopedInterfaces(current.Interfaces))) continue;
                            // Recreate only a mismatched owned rule so hidden interface scope
                            // cannot survive a property-only update.
                            rules.Remove(spec.Name); Release(ruleObject); ruleObject = null; existed = false;
                        }
                        if (apply)
                        {
                            if (ruleObject == null)
                            {
                                var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                                if (ruleType == null) throw new InvalidOperationException("Windows Firewall rule provider unavailable.");
                                ruleObject = Activator.CreateInstance(ruleType);
                                if (ruleObject == null) throw new InvalidOperationException("Windows Firewall rule creation failed.");
                            }
                            dynamic rule = ruleObject;
                            rule.Name = spec.Name; rule.Description = "Sentinel compiled port block policy; configuration read-back is not a packet test.";
                            rule.Grouping = "Sentinel Port Hardening";
                            rule.Enabled = false; rule.Protocol = spec.Protocol;
                            rule.Direction = spec.Direction; rule.Action = 0; rule.Profiles = 7;
                            rule.ApplicationName = ""; rule.ServiceName = "";
                            rule.LocalAddresses = "*"; rule.RemoteAddresses = "*";
                            rule.InterfaceTypes = "All"; rule.EdgeTraversal = false;
                            rule.LocalPorts = spec.Direction == 1 ? spec.Port.ToString() : "*";
                            rule.RemotePorts = spec.Direction == 2 ? spec.Port.ToString() : "*";
                            rule.Enabled = true;
                            if (!existed) rules.Add(rule);
                            Release(ruleObject); ruleObject = rules.Item(spec.Name); // fresh read-back
                        }
                        if (ruleObject == null) { missing++; continue; }
                        dynamic observed = ruleObject;
                        if (!Matches(spec, (bool)observed.Enabled, (int)observed.Action, (int)observed.Protocol,
                            (int)observed.Direction, (int)observed.Profiles, (string)observed.LocalPorts,
                            (string)observed.RemotePorts, (string)observed.ApplicationName, (string)observed.ServiceName,
                            (string)observed.LocalAddresses, (string)observed.RemoteAddresses, (string)observed.InterfaceTypes,
                            UnscopedInterfaces(observed.Interfaces))) missing++;
                    }
                    finally { Release(ruleObject); }
                }
                bool enabled = policy.FirewallEnabled[1] && policy.FirewallEnabled[2] && policy.FirewallEnabled[4];
                int modifyState = policy.LocalPolicyModifyState;
                return new PortBlockInspection
                {
                    Verified = missing == 0 && enabled && modifyState == 0,
                    Detail = "Owned port-rule mismatches=" + missing + "; all firewall profiles enabled=" + enabled +
                        "; local policy modify state=" + modifyState + ". Configuration read-back only; packet delivery and domain policy are not independently tested."
                };
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[PortHardening] " + ex);
                return new PortBlockInspection { Detail = "Windows Firewall port policy unavailable: " + ex.GetType().Name +
                    " (0x" + ex.HResult.ToString("X8") + "). No enforcement claim." };
            }
            finally { Release(rulesObject); Release(policyObject); }
        }

        internal static bool Matches(PortBlockSpec spec, bool enabled, int action, int protocol, int direction,
            int profiles, string? localPorts, string? remotePorts, string? application, string? service,
            string? localAddresses, string? remoteAddresses, string? interfaceTypes, bool unscopedInterfaces = true) =>
            unscopedInterfaces && enabled && action == 0 && protocol == spec.Protocol && direction == spec.Direction && (profiles & 7) == 7 &&
            localPorts == (spec.Direction == 1 ? spec.Port.ToString() : "*") &&
            remotePorts == (spec.Direction == 2 ? spec.Port.ToString() : "*") &&
            string.IsNullOrEmpty(application) && string.IsNullOrEmpty(service) &&
            localAddresses == "*" && remoteAddresses == "*" && string.Equals(interfaceTypes, "All", StringComparison.OrdinalIgnoreCase);

        private static bool UnscopedInterfaces(object? interfaces)
            => interfaces == null || interfaces is Array array && array.Length == 0;

        private static void Release(object? value)
        { if (value != null && Marshal.IsComObject(value)) Marshal.ReleaseComObject(value); }
    }
}
