using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
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
            string stage = "open firewall provider";
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
                        stage = "look up owned rule " + spec.Name;
                        ruleObject = ReadExistingRule(() => (object?)rules.Item(spec.Name));
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
                            stage = "replace mismatched owned rule " + spec.Name;
                            rules.Remove(spec.Name);
                            var old = ruleObject; ruleObject = null; Release(old); existed = false;
                        }
                        if (apply)
                        {
                            stage = "configure owned rule " + spec.Name;
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
                            // Fresh COM rule defaults apply to all applications/services.
                            // Do not depend on setters accepting empty BSTRs; verify defaults below.
                            rule.LocalAddresses = "*"; rule.RemoteAddresses = "*";
                            rule.InterfaceTypes = "All"; rule.EdgeTraversal = false;
                            rule.LocalPorts = spec.Direction == 1 ? spec.Port.ToString() : "*";
                            rule.RemotePorts = spec.Direction == 2 ? spec.Port.ToString() : "*";
                            rule.Enabled = true;
                            stage = "install owned rule " + spec.Name;
                            if (!existed) rules.Add(rule);
                            var installed = ruleObject; ruleObject = null; Release(installed);
                            stage = "read back owned rule " + spec.Name;
                            ruleObject = rules.Item(spec.Name); // mandatory fresh read-back; missing is a failure here
                        }
                        if (ruleObject == null) { missing++; continue; }
                        stage = "verify owned rule " + spec.Name;
                        dynamic observed = ruleObject;
                        if (!Matches(spec, (bool)observed.Enabled, (int)observed.Action, (int)observed.Protocol,
                            (int)observed.Direction, (int)observed.Profiles, (string)observed.LocalPorts,
                            (string)observed.RemotePorts, (string)observed.ApplicationName, (string)observed.ServiceName,
                            (string)observed.LocalAddresses, (string)observed.RemoteAddresses, (string)observed.InterfaceTypes,
                            UnscopedInterfaces(observed.Interfaces))) missing++;
                    }
                    finally { Release(ruleObject); }
                }
                stage = "read firewall profile and policy state";
                bool enabled = true;
                foreach (int profile in new[] { 1, 2, 4 }) enabled &= (bool)policy.FirewallEnabled[profile];
                int modifyState = (int)policy.LocalPolicyModifyState;
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
                    " (0x" + ex.HResult.ToString("X8") + ") during " + stage + ": " + ex.Message + ". No enforcement claim." };
            }
            finally { Release(rulesObject); Release(policyObject); }
        }

        internal static object? ReadExistingRule(Func<object?> read)
        {
            try { return read(); }
            // COM interop maps HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) to
            // FileNotFoundException on Framework. Only genuine absence permits creation.
            catch (Exception ex) when ((ex is COMException || ex is FileNotFoundException) &&
                ((uint)ex.HResult == 0x80070002 || (uint)ex.HResult == 0x80070490))
            { Debug.WriteLine("[PortHardening] Owned rule absent: " + ex.Message); return null; }
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
