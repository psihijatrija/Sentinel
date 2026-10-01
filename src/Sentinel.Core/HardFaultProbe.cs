using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    /// <summary>
    /// Reads the same per-process hard-fault counter LatencyMon uses
    /// (<c>SYSTEM_PROCESS_INFORMATION.HardFaultCount</c>, Windows 7+).
    /// </summary>
    internal static class HardFaultProbe
    {
        private const int SystemProcessInformation = 5;
        private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MEMORY_COUNTERS_EX
        {
            public int cb;
            public uint PageFaultCount;
            public UIntPtr PeakWorkingSetSize;
            public UIntPtr WorkingSetSize;
            public UIntPtr QuotaPeakPagedPoolUsage;
            public UIntPtr QuotaPagedPoolUsage;
            public UIntPtr QuotaPeakNonPagedPoolUsage;
            public UIntPtr QuotaNonPagedPoolUsage;
            public UIntPtr PagefileUsage;
            public UIntPtr PeakPagefileUsage;
            public UIntPtr PrivateUsage;
        }

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool GetProcessMemoryInfo(
            IntPtr hProcess, out PROCESS_MEMORY_COUNTERS_EX counters, int cb);

        [DllImport("psapi.dll", SetLastError = true)]
        internal static extern bool EmptyWorkingSet(IntPtr hProcess);

        public readonly struct Snapshot
        {
            public Snapshot(uint hardFaults, uint pageFaults, long workingSetBytes, bool hardFaultsValid)
            {
                HardFaults = hardFaults;
                PageFaults = pageFaults;
                WorkingSetBytes = workingSetBytes;
                HardFaultsValid = hardFaultsValid;
            }

            public uint HardFaults { get; }
            public uint PageFaults { get; }
            public long WorkingSetBytes { get; }
            public bool HardFaultsValid { get; }

            public static Snapshot Delta(Snapshot before, Snapshot after) =>
                new Snapshot(
                    after.HardFaults >= before.HardFaults ? after.HardFaults - before.HardFaults : 0,
                    after.PageFaults >= before.PageFaults ? after.PageFaults - before.PageFaults : 0,
                    after.WorkingSetBytes - before.WorkingSetBytes,
                    before.HardFaultsValid && after.HardFaultsValid);
        }

        public static Snapshot ReadCurrent()
        {
            int pid = Process.GetCurrentProcess().Id;
            bool hardOk = TryGetHardFaultCount(pid, out uint hard);
            uint pageFaults = 0;
            long ws = 0;
            try
            {
                using var proc = Process.GetCurrentProcess();
                ws = proc.WorkingSet64;
                var h = proc.Handle;
                var pmc = new PROCESS_MEMORY_COUNTERS_EX { cb = Marshal.SizeOf<PROCESS_MEMORY_COUNTERS_EX>() };
                if (GetProcessMemoryInfo(h, out pmc, pmc.cb))
                    pageFaults = pmc.PageFaultCount;
            }
            catch
            {
                /* best-effort */
            }

            return new Snapshot(hardOk ? hard : 0, pageFaults, ws, hardOk);
        }

        public static bool TryGetHardFaultCount(int pid, out uint hardFaults)
        {
            hardFaults = 0;
            int size = 512 * 1024;
            for (int attempt = 0; attempt < 4; attempt++)
            {
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    int status = NativeResolver.NtQuerySystemInformation(
                        SystemProcessInformation, buf, size, out int needed);
                    if (status == StatusInfoLengthMismatch)
                    {
                        size = Math.Max(needed + 64 * 1024, size * 2);
                        continue;
                    }

                    if (status != 0)
                        return false;

                    return WalkForPid(buf, size, pid, out hardFaults);
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }

            return false;
        }

        private static bool WalkForPid(IntPtr buf, int bufSize, int pid, out uint hardFaults)
        {
            hardFaults = 0;
            int pidOffset = IntPtr.Size == 8 ? 0x50 : 0x44;
            int offset = 0;
            int guard = 0;

            while (offset >= 0 && offset + pidOffset + IntPtr.Size <= bufSize && guard++ < 8192)
            {
                int next = Marshal.ReadInt32(buf, offset);
                uint hard = unchecked((uint)Marshal.ReadInt32(buf, offset + 0x10));
                IntPtr unique = Marshal.ReadIntPtr(buf, offset + pidOffset);
                if (unchecked((int)unique.ToInt64()) == pid)
                {
                    hardFaults = hard;
                    return true;
                }

                if (next <= 0)
                    break;
                offset += next;
            }

            return false;
        }
    }
}
