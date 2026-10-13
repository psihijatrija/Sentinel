using System;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    /// <summary>
    /// Transparent Win32/NT P/Invoke surface for EDR process inspection.
    ///
    /// v2.3.6 lesson (Kaspersky): split-string / GetProcAddress "hiding" of API names is
    /// scored as evasion by ML engines and is worse than a normal import table.
    /// v2.3.8: plain [DllImport] declarations - auditable, no dynamic resolution.
    /// Authenticode signing remains the path to near-zero VirusTotal detections.
    /// </summary>
    internal static class NativeResolver
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
            out NativeProcessMemory.MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
            int dwDesiredAccess, bool bInheritHandle, int dwOptions);

        // Module enumeration (psapi). Exposed via kernel32 forwarders so the import
        // table stays auditable. EnumProcessModulesEx + LIST_MODULES_ALL is the only
        // reliable way for a 64-bit process to enumerate a 32-bit (WOW64) target's
        // modules; Process.Modules / EnumProcessModules alone silently misses them.
        public const uint LIST_MODULES_DEFAULT = 0x0;
        public const uint LIST_MODULES_32BIT = 0x01;
        public const uint LIST_MODULES_64BIT = 0x02;
        public const uint LIST_MODULES_ALL = 0x03;

        [StructLayout(LayoutKind.Sequential)]
        public struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool EnumProcessModulesEx(IntPtr hProcess,
            [Out] IntPtr[] lphModule, int cb, out int lpcbNeeded, uint dwFilterFlag);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int GetModuleFileNameExW(IntPtr hProcess, IntPtr hModule,
            [Out] System.Text.StringBuilder lpFilename, int nSize);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int GetModuleBaseNameW(IntPtr hProcess, IntPtr hModule,
            [Out] System.Text.StringBuilder lpBaseName, int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule,
            out MODULEINFO lpmodinfo, int cb);

        [DllImport("ntdll.dll")]
        public static extern int NtQuerySystemInformation(int systemInformationClass,
            IntPtr systemInformation, int systemInformationLength, out int returnLength);

        [DllImport("ntdll.dll")]
        public static extern int NtQueryObject(IntPtr handle, int infoClass,
            IntPtr buffer, int bufferSize, out int returnLength);

        [DllImport("ntdll.dll", EntryPoint = "NtQueryInformationProcess")]
        private static extern int NtQueryInformationProcessNative(IntPtr processHandle,
            int processInformationClass, IntPtr processInformation,
            int processInformationLength, out int returnLength);

        /// <summary>
        /// Calls NtQueryInformationProcess with a pinned struct buffer.
        /// </summary>
        public static int NtQueryInformationProcess<T>(IntPtr processHandle, int infoClass, ref T info, out int returnLength)
            where T : struct
        {
            int size = Marshal.SizeOf<T>();
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(info, buffer, false);
                int status = NtQueryInformationProcessNative(processHandle, infoClass, buffer, size, out returnLength);
                if (status == 0)
                    info = Marshal.PtrToStructure<T>(buffer);
                return status;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
