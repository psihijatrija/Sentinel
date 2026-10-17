using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Sentinel.Core
{
    public sealed class WindowsDnsConfigurationBackend : IDnsConfigurationBackend
    {
        private const string V4Key = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
        private const string V6Key = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";
        public IReadOnlyList<DnsAdapterState> Inspect()
        {
            bool managed = IsPolicyManaged();
            var result = new List<DnsAdapterState>();
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                var state = new DnsAdapterState { Id = adapter.Id, Name = adapter.Name, PolicyManaged = managed, InspectionComplete = false };
                try
                {
                    state.SupportsIpv4 = adapter.Supports(NetworkInterfaceComponent.IPv4);
                    state.SupportsIpv6 = adapter.Supports(NetworkInterfaceComponent.IPv6);
                    state.Ipv4Static = ReadStatic(V4Key, adapter.Id);
                    state.Ipv6Static = ReadStatic(V6Key, adapter.Id);
                    state.EffectiveServers = adapter.GetIPProperties().DnsAddresses.Select(a => a.ToString()).ToArray();
                    state.InspectionComplete = true;
                    bool physicalShape = adapter.NetworkInterfaceType == NetworkInterfaceType.Ethernet
                        || adapter.NetworkInterfaceType == NetworkInterfaceType.Wireless80211;
                    bool virtualShape = new[] { "virtual", "hyper-v", "vmware", "vpn", "wintun", "tap-" }
                        .Any(x => adapter.Description.IndexOf(x, StringComparison.OrdinalIgnoreCase) >= 0);
                    state.Eligible = Guid.TryParse(adapter.Id, out _) && physicalShape && !virtualShape
                        && adapter.OperationalStatus == OperationalStatus.Up && !managed;
                    if (state.Eligible)
                    {
                        try { ProbeNativeApi(new Guid(adapter.Id)); }
                        catch (Exception ex) { state.Eligible = false; state.Detail = "DNS configuration API unavailable: " + ex.Message; }
                    }
                    if (state.Detail.Length == 0) state.Detail = managed ? "Domain/NRPT/DNS policy detected; use the organization's network administration."
                        : !state.Eligible ? "Only connected, unmanaged Ethernet/Wi-Fi adapters are eligible."
                        : "Resolver trust is unverified. Empty static settings mean automatic DNS configuration.";
                }
                catch (Exception ex) { state.Eligible = false; state.Detail = "Inspection incomplete: " + ex.Message; }
                result.Add(state);
            }
            return result;
        }
        private static string ReadStatic(string root, string id)
        {
            using var key = Registry.LocalMachine.OpenSubKey(root + @"\" + new Guid(id).ToString("B"));
            return key?.GetValue("NameServer") as string ?? "";
        }
        private static bool IsPolicyManaged()
        {
            foreach (string path in new[] {
                @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig",
                @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig" })
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key != null && (key.SubKeyCount > 0 || key.ValueCount > 0)) return true;
            }
            using (var dnsPolicy = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"))
            {
                // Unrelated LLMNR/DoH hardening values are not resolver assignment policy.
                if (dnsPolicy?.GetValue("NameServer") != null || dnsPolicy?.GetValue("DnsServers") != null) return true;
            }
            IntPtr name = IntPtr.Zero;
            try
            {
                int error = NetGetJoinInformation(null, out name, out int status);
                if (error != 0) throw new Win32Exception(error, "Cannot establish domain-management state.");
                return status == 3; // NetSetupDomainName
            }
            finally { if (name != IntPtr.Zero) NetApiBufferFree(name); }
        }
        public void SetServers(string adapterId, AddressFamily family, string servers)
        {
            if (family != AddressFamily.InterNetwork && family != AddressFamily.InterNetworkV6)
                throw new ArgumentException("Unsupported address family.");
            // Re-check administrative scope immediately before each mutation.
            var current = Inspect().SingleOrDefault(a => a.Id.Equals(adapterId, StringComparison.OrdinalIgnoreCase));
            if (current == null || !current.Eligible || current.PolicyManaged)
                throw new InvalidOperationException("Adapter scope or policy changed; DNS mutation refused.");
            foreach (string address in DnsRepairService.Servers(servers))
                if (System.Net.IPAddress.Parse(address).AddressFamily != family)
                    throw new ArgumentException("Resolver address family mismatch.");
            IntPtr text = Marshal.StringToHGlobalUni(servers);
            try
            {
                var settings = new DnsInterfaceSettings
                {
                    Version = 1, Flags = 2UL | (family == AddressFamily.InterNetworkV6 ? 1UL : 0UL), NameServer = text
                };
                uint error = SetInterfaceDnsSettings(new Guid(adapterId), ref settings);
                if (error != 0) throw new Win32Exception((int)error, "Windows refused DNS settings for " + family);
            }
            catch (EntryPointNotFoundException ex)
            { throw new NotSupportedException("This Windows version does not expose the DNS configuration API; no registry-only fallback is used.", ex); }
            finally { if (text != IntPtr.Zero) Marshal.FreeHGlobal(text); }
        }
        internal static void ProbeNativeApi(Guid adapterId)
        {
            var settings = new DnsInterfaceSettings { Version = 1 };
            uint error = GetInterfaceDnsSettings(adapterId, ref settings);
            if (error != 0) throw new Win32Exception((int)error, "Windows DNS settings cannot be queried.");
            FreeInterfaceDnsSettings(ref settings);
        }
        public bool FlushCache() => DnsFlushResolverCache();
        [StructLayout(LayoutKind.Sequential)]
        private struct DnsInterfaceSettings
        {
            public uint Version;
            public ulong Flags;
            public IntPtr Domain, NameServer, SearchList;
            public uint RegistrationEnabled, RegisterAdapterName, EnableLLMNR, QueryAdapterName;
            public IntPtr ProfileNameServer;
        }
        // netioapi.h / DNS_INTERFACE_SETTINGS_VERSION1. GUID is passed by value.
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern uint SetInterfaceDnsSettings(Guid interfaceId, ref DnsInterfaceSettings settings);
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern uint GetInterfaceDnsSettings(Guid interfaceId, ref DnsInterfaceSettings settings);
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern void FreeInterfaceDnsSettings(ref DnsInterfaceSettings settings);
        [DllImport("dnsapi.dll", SetLastError = true)]
        private static extern bool DnsFlushResolverCache();
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetGetJoinInformation(string? server, out IntPtr name, out int status);
        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);
    }
}
