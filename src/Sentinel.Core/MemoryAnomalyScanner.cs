using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    public enum MemoryAnomalyType
    {
        UnbackedExecutable,
        ReflectivePeHeader,
        WipedModuleHeader,
        SuspiciousRwx
    }

    public sealed class MemoryAnomalyEntry
    {
        public IntPtr BaseAddress { get; set; }
        public long RegionSize { get; set; }
        public uint State { get; set; }
        public uint Protect { get; set; }
        public uint Type { get; set; }
        public string ProtectionString { get; set; } = string.Empty;
        public string TypeString { get; set; } = string.Empty;
        public MemoryAnomalyType AnomalyType { get; set; }
        public string Severity { get; set; } = "Medium";
        public string Description { get; set; } = string.Empty;
    }

    /// <summary>
    /// Inspects remote process virtual memory to detect in-memory threats:
    /// - Unbacked executable memory (PAGE_EXECUTE_* in MEM_PRIVATE)
    /// - Reflective DLL / manual PE injection (MZ/PE headers in private memory)
    /// - Wiped PE headers (MEM_IMAGE base addresses with zeroed MZ headers)
    /// - Suspicious RWX memory allocations in non-JIT hosts
    /// </summary>
    public static class MemoryAnomalyScanner
    {
        public const uint MEM_PRIVATE = 0x20000;
        public const uint MEM_MAPPED = 0x40000;
        public const uint MEM_IMAGE = NativeProcessMemory.TypeImage;

        // Maximum memory regions to inspect per process to prevent runaway scans
        private const int MaxRegions = 8192;

        // User-mode virtual address space ceiling for x64 Windows
        private const long MaxUserModeAddress = 0x7FFFFFFF0000;

        /// <summary>
        /// Known runtimes that legitimately allocate executable private memory for JIT compilation.
        /// </summary>
        private static readonly HashSet<string> KnownJitModules = new(StringComparer.OrdinalIgnoreCase)
        {
            "clr.dll", "coreclr.dll", "clrjit.dll", "mscorwks.dll",
            "v8.dll", "node.dll", "jscript9.dll", "chakra.dll"
        };

        /// <summary>
        /// Inspects the target process for memory anomalies.
        /// </summary>
        public static List<MemoryAnomalyEntry> ScanProcess(int processId, string? imagePath = null)
        {
            var anomalies = new List<MemoryAnomalyEntry>();
            if (processId <= 4) return anomalies;

            if (!NativeProcessMemory.CanInspect(processId, imagePath))
                return anomalies;

            IntPtr hProcess = NativeProcessMemory.OpenRemoteHandle(
                NativeProcessMemory.AccessQuery | NativeProcessMemory.AccessVmRead, processId);

            if (hProcess == IntPtr.Zero)
                return anomalies;

            try
            {
                // Check if the process is hosting a JIT runtime
                bool isJitHost = DetectJitHost(processId);

                IntPtr address = IntPtr.Zero;
                int regionsExamined = 0;
                var buffer = new byte[1024];

                while (regionsExamined++ < MaxRegions)
                {
                    int res = NativeResolver.VirtualQueryEx(
                        hProcess, address, out var mbi, Marshal.SizeOf<NativeProcessMemory.MEMORY_BASIC_INFORMATION>());

                    if (res <= 0) break;

                    long baseVal = mbi.BaseAddress.ToInt64();
                    long regionSize = mbi.RegionSize.ToInt64();

                    if (baseVal < 0 || baseVal >= MaxUserModeAddress || regionSize <= 0)
                        break;

                    // Only analyze committed memory
                    if (mbi.State == NativeProcessMemory.StateCommit)
                    {
                        bool isExec = NativeProcessMemory.IsExecutableProtection(mbi.Protect);

                        if (isExec)
                        {
                            AnalyzeExecutableRegion(hProcess, mbi, isJitHost, buffer, anomalies);
                        }
                    }

                    long nextVal = baseVal + regionSize;
                    if (nextVal <= baseVal || nextVal >= MaxUserModeAddress)
                        break;

                    address = new IntPtr(nextVal);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[MemoryAnomalyScanner] Scan failed for PID {processId}: {ex.Message}");
            }
            finally
            {
                NativeProcessMemory.CloseHandle(hProcess);
            }

            return anomalies;
        }

        private static void AnalyzeExecutableRegion(
            IntPtr hProcess,
            NativeProcessMemory.MEMORY_BASIC_INFORMATION mbi,
            bool isJitHost,
            byte[] probeBuffer,
            List<MemoryAnomalyEntry> anomalies)
        {
            string protStr = FormatProtection(mbi.Protect);
            string typeStr = FormatType(mbi.Type);
            long regionSize = mbi.RegionSize.ToInt64();

            // Case 1: Unbacked Executable Memory (MEM_PRIVATE or MEM_MAPPED with executable protection)
            if (mbi.Type != MEM_IMAGE)
            {
                bool hasBytes = NativeProcessMemory.CopyRemote(hProcess, mbi.BaseAddress, probeBuffer, out int bytesRead);

                // Check for reflective PE header in private memory (smoking gun)
                if (hasBytes && bytesRead >= 64 && IsReflectivePeHeader(probeBuffer, bytesRead))
                {
                    anomalies.Add(new MemoryAnomalyEntry
                    {
                        BaseAddress = mbi.BaseAddress,
                        RegionSize = regionSize,
                        State = mbi.State,
                        Protect = mbi.Protect,
                        Type = mbi.Type,
                        ProtectionString = protStr,
                        TypeString = typeStr,
                        AnomalyType = MemoryAnomalyType.ReflectivePeHeader,
                        Severity = "Critical",
                        Description = $"Reflective PE image header (MZ/PE) detected in unbacked {typeStr} memory."
                    });
                    return;
                }

                // RWX memory in non-JIT hosts is a strong indicator of shellcode / staging
                if (mbi.Protect == NativeProcessMemory.ProtRWX)
                {
                    if (!isJitHost)
                    {
                        anomalies.Add(new MemoryAnomalyEntry
                        {
                            BaseAddress = mbi.BaseAddress,
                            RegionSize = regionSize,
                            State = mbi.State,
                            Protect = mbi.Protect,
                            Type = mbi.Type,
                            ProtectionString = protStr,
                            TypeString = typeStr,
                            AnomalyType = MemoryAnomalyType.SuspiciousRwx,
                            Severity = "High",
                            Description = $"Unbacked PAGE_EXECUTE_READWRITE memory in non-JIT host (potential shellcode/hook buffer)."
                        });
                        return;
                    }
                }

                // If not JIT host, flag any executable private memory
                if (!isJitHost)
                {
                    anomalies.Add(new MemoryAnomalyEntry
                    {
                        BaseAddress = mbi.BaseAddress,
                        RegionSize = regionSize,
                        State = mbi.State,
                        Protect = mbi.Protect,
                        Type = mbi.Type,
                        ProtectionString = protStr,
                        TypeString = typeStr,
                        AnomalyType = MemoryAnomalyType.UnbackedExecutable,
                        Severity = "Medium",
                        Description = $"Executable code mapped into {typeStr} memory without backing disk image."
                    });
                }
            }
            // Case 2: MEM_IMAGE module where the PE DOS header has been wiped/zeroed
            else if (mbi.BaseAddress == mbi.AllocationBase)
            {
                if (NativeProcessMemory.CopyRemote(hProcess, mbi.BaseAddress, probeBuffer, out int bytesRead) && bytesRead >= 2)
                {
                    if (probeBuffer[0] == 0 && probeBuffer[1] == 0)
                    {
                        anomalies.Add(new MemoryAnomalyEntry
                        {
                            BaseAddress = mbi.BaseAddress,
                            RegionSize = regionSize,
                            State = mbi.State,
                            Protect = mbi.Protect,
                            Type = mbi.Type,
                            ProtectionString = protStr,
                            TypeString = typeStr,
                            AnomalyType = MemoryAnomalyType.WipedModuleHeader,
                            Severity = "High",
                            Description = "Mapped module image base has a zeroed/wiped DOS header (anti-dumping / evasion technique)."
                        });
                    }
                }
            }
        }

        /// <summary>
        /// Evaluates whether a memory buffer begins with a valid DOS MZ header and PE signature.
        /// </summary>
        public static bool IsReflectivePeHeader(byte[] buffer, int length)
        {
            if (buffer == null || length < 64) return false;
            if (buffer[0] != (byte)'M' || buffer[1] != (byte)'Z') return false;

            // Offset 0x3C contains the offset to the PE signature
            int peOffset = BitConverter.ToInt32(buffer, 0x3C);
            if (peOffset < 0 || peOffset + 4 > length) return false;

            return buffer[peOffset] == (byte)'P' &&
                   buffer[peOffset + 1] == (byte)'E' &&
                   buffer[peOffset + 2] == 0 &&
                   buffer[peOffset + 3] == 0;
        }

        /// <summary>
        /// Checks if a process hosts a known JIT compiler (.NET CLR or JavaScript V8/Chakra).
        /// </summary>
        public static bool DetectJitHost(int processId)
        {
            try
            {
                var modules = NativeProcessMemory.EnumModules(processId);
                return modules.Any(m => KnownJitModules.Contains(m.Name));
            }
            catch
            {
                return false;
            }
        }

        public static string FormatProtection(uint protect) => protect switch
        {
            NativeProcessMemory.ProtX => "PAGE_EXECUTE",
            NativeProcessMemory.ProtRX => "PAGE_EXECUTE_READ",
            NativeProcessMemory.ProtRWX => "PAGE_EXECUTE_READWRITE",
            NativeProcessMemory.ProtXwc => "PAGE_EXECUTE_WRITECOPY",
            0x01 => "PAGE_NOACCESS",
            0x02 => "PAGE_READONLY",
            0x04 => "PAGE_READWRITE",
            0x08 => "PAGE_WRITECOPY",
            _ => $"0x{protect:X2}"
        };

        public static string FormatType(uint type) => type switch
        {
            MEM_IMAGE => "MEM_IMAGE",
            MEM_MAPPED => "MEM_MAPPED",
            MEM_PRIVATE => "MEM_PRIVATE",
            _ => $"0x{type:X6}"
        };
    }
}
