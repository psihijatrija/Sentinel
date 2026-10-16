using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    /// <summary>Windows Firewall COM adapter. No shell invocation; never replaces pre-existing rules.</summary>
    public sealed class WindowsFirewallIsolationStore : IFirewallIsolationStore
    {
        public IReadOnlyList<FirewallIsolationRule> Find(string name)
        {
            object? policy = null, rules = null;
            var found = new List<FirewallIsolationRule>();
            try
            {
                policy = Create("HNetCfg.FwPolicy2");
                rules = ((dynamic)policy).Rules;
                foreach (object item in (System.Collections.IEnumerable)rules)
                {
                    try
                    {
                        dynamic rule = item;
                        if ((string)rule.Name != name) continue;
                        // COM may expand a single IPv4 host into an equivalent /32 netmask.
                        string remote = rule.RemoteAddresses;
                        if (remote.EndsWith("/255.255.255.255", StringComparison.Ordinal)) remote = remote.Substring(0, remote.IndexOf('/'));
                        if (remote.EndsWith("/128", StringComparison.Ordinal) || remote.EndsWith("/32", StringComparison.Ordinal)) remote = remote.Substring(0, remote.IndexOf('/'));
                        if (System.Net.IPAddress.TryParse(remote, out var ip)) remote = ip.ToString();
                        object? interfaces = rule.Interfaces;
                        found.Add(new FirewallIsolationRule
                        {
                            Name = rule.Name, Description = rule.Description, RemoteAddress = remote,
                            Direction = rule.Direction, Action = rule.Action, Enabled = rule.Enabled,
                            Profiles = rule.Profiles, Protocol = rule.Protocol, Application = rule.ApplicationName ?? "",
                            Service = rule.ServiceName ?? "", LocalAddresses = rule.LocalAddresses ?? "*",
                            // Ports are not meaningful for protocol ANY and COM may refuse their getters.
                            LocalPorts = (int)rule.Protocol == 256 ? "*" : rule.LocalPorts,
                            RemotePorts = (int)rule.Protocol == 256 ? "*" : rule.RemotePorts,
                            InterfaceTypes = rule.InterfaceTypes, Grouping = rule.Grouping ?? "", EdgeTraversal = rule.EdgeTraversal,
                            Interfaces = interfaces is Array values ? values.Cast<object>().Select(value => Convert.ToString(value) ?? "").ToArray() : Array.Empty<string>()
                        });
                    }
                    finally { Release(item); }
                }
                return found;
            }
            finally { Release(rules); Release(policy); }
        }

        public void Add(FirewallIsolationRule expected)
        {
            if (Find(expected.Name).Count != 0) throw new InvalidOperationException("Firewall rule name is already in use.");
            object? policy = null, rules = null, instance = null;
            try
            {
                policy = Create("HNetCfg.FwPolicy2");
                rules = ((dynamic)policy).Rules;
                instance = Create("HNetCfg.FWRule");
                dynamic rule = instance;
                rule.Name = expected.Name; rule.Description = expected.Description;
                rule.Protocol = expected.Protocol; rule.Direction = expected.Direction;
                rule.RemoteAddresses = expected.RemoteAddress; rule.LocalAddresses = expected.LocalAddresses;
                rule.Action = expected.Action; rule.Enabled = expected.Enabled; rule.Profiles = expected.Profiles;
                rule.InterfaceTypes = expected.InterfaceTypes; rule.EdgeTraversal = expected.EdgeTraversal;
                ((dynamic)rules).Add(rule);
            }
            finally { Release(instance); Release(rules); Release(policy); }
        }
        public void Remove(string name)
        {
            object? policy = null, rules = null;
            try
            {
                policy = Create("HNetCfg.FwPolicy2"); rules = ((dynamic)policy).Rules;
                ((dynamic)rules).Remove(name);
            }
            finally { Release(rules); Release(policy); }
        }
        private static object Create(string name)
        {
            var type = Type.GetTypeFromProgID(name) ?? throw new PlatformNotSupportedException("Windows Firewall COM is unavailable.");
            return Activator.CreateInstance(type) ?? throw new InvalidOperationException("Windows Firewall COM creation failed.");
        }
        private static void Release(object? value)
        {
            if (value != null && Marshal.IsComObject(value)) Marshal.FinalReleaseComObject(value);
        }
    }
}
