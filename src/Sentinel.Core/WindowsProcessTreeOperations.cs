using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Sentinel.Core
{
    internal sealed class WindowsProcessTreeOperations : IProcessTreeOperations
    {
        internal static long GetCreationTime(int pid)
        {
            using var handle = new SafeProcessHandle(NativeResolver.OpenProcess(0x1000, false, pid), ownsHandle: true);
            if (handle.IsInvalid || !GetProcessTimes(handle, out long created, out _, out _, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return created;
        }

        public IReadOnlyList<ProcessTreeEntry> Snapshot()
        {
            using var snapshot = CreateToolhelp32Snapshot(2, 0); // TH32CS_SNAPPROCESS
            if (snapshot.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            var entry = new ProcessEntry { Size = (uint)Marshal.SizeOf<ProcessEntry>() };
            var entries = new List<ProcessTreeEntry>();
            if (!Process32First(snapshot, ref entry))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            do { entries.Add(new ProcessTreeEntry((int)entry.ProcessId, (int)entry.ParentProcessId)); }
            while (Process32Next(snapshot, ref entry));
            int error = Marshal.GetLastWin32Error();
            if (error != 18) throw new Win32Exception(error); // ERROR_NO_MORE_FILES
            return entries;
        }

        public IProcessTreeTarget? Open(int pid)
        {
            // Query identity, terminate, and wait; never request PROCESS_ALL_ACCESS.
            var handle = new SafeProcessHandle(
                NativeResolver.OpenProcess(0x1000 | 0x0001 | 0x00100000, false, pid), ownsHandle: true);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                if (error == 87) return null; // ERROR_INVALID_PARAMETER: process no longer exists
                throw new Win32Exception(error);
            }
            try { return new Target(pid, handle); }
            catch { handle.Dispose(); throw; }
        }

        private sealed class Target : IProcessTreeTarget
        {
            private readonly SafeProcessHandle _handle;
            public int ProcessId { get; }
            public long CreationTime { get; }
            public bool CanTerminate { get; }
            public Target(int pid, SafeProcessHandle handle)
            {
                _handle = handle;
                ProcessId = pid;
                if (!GetProcessTimes(handle, out long created, out _, out _, out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                CreationTime = created;
                var path = new StringBuilder(32768);
                int length = path.Capacity;
                if (!QueryFullProcessImageName(handle, 0, path, ref length))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                CanTerminate = HardeningModule.CanTerminateProcess(pid, Path.GetFileNameWithoutExtension(path.ToString()), path.ToString());
            }
            public bool HasExited
            {
                get
                {
                    uint status = WaitForSingleObject(_handle, 0);
                    if (status == 0xFFFFFFFF) throw new Win32Exception(Marshal.GetLastWin32Error());
                    return status == 0;
                }
            }
            public bool TerminateAndWait(int timeoutMilliseconds)
            {
                return NativeProcessExitVerifier.TerminateAndWait(ProcessId, timeoutMilliseconds,
                    () => TerminateProcess(_handle, 1),
                    () => Marshal.GetLastWin32Error(),
                    timeout => WaitForSingleObject(_handle, (uint)timeout));
            }
            public void Dispose() => _handle.Dispose();
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ProcessEntry
        {
            public uint Size, Usage, ProcessId;
            public UIntPtr DefaultHeapId;
            public uint ModuleId, Threads, ParentProcessId;
            public int Priority;
            public uint Flags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Executable;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint processId);
        [DllImport("kernel32.dll", EntryPoint = "Process32FirstW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Process32First(SafeFileHandle snapshot, ref ProcessEntry entry);
        [DllImport("kernel32.dll", EntryPoint = "Process32NextW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Process32Next(SafeFileHandle snapshot, ref ProcessEntry entry);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder path, ref int length);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);
    }
}
