using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    public interface INetworkCacheInvalidator
    {
        void FlushDns();
        void FlushArp(string ip);
    }
    public sealed class WindowsNetworkCacheInvalidator : INetworkCacheInvalidator
    {
        public void FlushDns()
        {
            try
            {
                // DnsFlushResolverCache is a documented public API - not a shell-out
                DnsFlushResolverCache();
            }
            catch (Exception ex) { Debug.WriteLine("Network cache invalidation unavailable: " + ex.GetType().Name); }
        }

        /// <summary>
        /// v1.8.1: Drop a single IPv4 ARP cache entry without shelling to <c>arp.exe</c>.
        /// Restores NetworkIsolate parity with v5.9.0 (firewall + ARP + DNS flush).
        /// </summary>
        public void FlushArp(string ip)
        {
            try
            {
                if (!IPAddress.TryParse(ip, out var addr) ||
                    addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    return;

                var ipBytes = addr.GetAddressBytes();
                uint ipInt = BitConverter.ToUInt32(ipBytes, 0);
                if (GetBestInterface(ipInt, out int ifIndex) != 0)
                    return;

                var row = new MibIpNetRow
                {
                    dwIndex = ifIndex,
                    dwAddr = unchecked((int)ipInt)
                };
                DeleteIpNetEntry(ref row);
            }
            catch (Exception ex) { Debug.WriteLine("Network cache invalidation unavailable: " + ex.GetType().Name); }
        }

        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        private static extern uint DnsFlushResolverCache();

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetBestInterface(uint dwDestAddr, out int pdwBestIfIndex);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int DeleteIpNetEntry(ref MibIpNetRow pArpEntry);

        [StructLayout(LayoutKind.Sequential)]
        private struct MibIpNetRow
        {
            public int dwIndex;
            public int dwPhysAddrLen;
            public byte mac0, mac1, mac2, mac3, mac4, mac5, mac6, mac7;
            public int dwAddr;
            public int dwType;
        }

    }
}
