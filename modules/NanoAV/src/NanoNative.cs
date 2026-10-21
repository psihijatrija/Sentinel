using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace NanoAV
{
    // P/Invoke layer. Replaces PowerShell's Get-NetTCPConnection (via
    // iphlpapi!GetExtendedTcpTable) and the psapi!EmptyWorkingSet working-set
    // trim used by the original script.
    internal static class Native
    {
        [DllImport("psapi.dll")]
        public static extern bool EmptyWorkingSet(IntPtr hProcess);

        // GetExtendedTcpTable - enumerate TCP connections with owning PID.
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
            int ipVersion, int tableClass, int reserved);

        private const int AF_INET = 2;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;

        // MIB_TCPROW_OWNER_PID state 5 == ESTABLISHED, 2 == LISTEN.
        public const int STATE_ESTABLISHED = 5;
        public const int STATE_LISTEN = 2;

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;   // bytes 0..1 used (network order)
            public uint remoteAddr;
            public uint remotePort;  // bytes 0..1 used (network order)
            public uint owningPid;
        }

        public sealed class TcpConnection
        {
            public int State;
            public string LocalAddress;
            public int LocalPort;
            public string RemoteAddress;
            public int RemotePort;
            public int OwningProcess;
        }

        public static List<TcpConnection> GetTcpConnections()
        {
            var result = new List<TcpConnection>();
            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET,
                TCP_TABLE_OWNER_PID_ALL, 0);

            IntPtr tcpTable = Marshal.AllocHGlobal(bufferSize);
            try
            {
                uint ret = GetExtendedTcpTable(tcpTable, ref bufferSize, true, AF_INET,
                    TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) return result;

                int rowCount = Marshal.ReadInt32(tcpTable);
                IntPtr rowPtr = (IntPtr)((long)tcpTable + 4);
                int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));

                for (int i = 0; i < rowCount; i++)
                {
                    var row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    result.Add(new TcpConnection
                    {
                        State = (int)row.state,
                        LocalAddress = new IPAddress(row.localAddr).ToString(),
                        LocalPort = DecodePort(row.localPort),
                        RemoteAddress = new IPAddress(row.remoteAddr).ToString(),
                        RemotePort = DecodePort(row.remotePort),
                        OwningProcess = (int)row.owningPid
                    });
                    rowPtr = (IntPtr)((long)rowPtr + rowSize);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTable);
            }
            return result;
        }

        private static int DecodePort(uint port)
        {
            // Port is stored in network byte order in the low 16 bits.
            return ((int)(port & 0xFF) << 8) | (int)((port >> 8) & 0xFF);
        }
    }
}
