using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    /// <summary>
    /// Remote process inspection primitives used by the EDR engine.
    /// Standard read-only inspection and handle operations - transparent to AV scanners.
    /// </summary>
    internal static class NativeProcessMemory
    {
        public const uint AccessQuery = 0x0400;
        public const uint AccessQueryLimited = 0x1000;
        public const uint AccessVmRead = 0x0010;
        public const uint StateCommit = 0x1000;
        public const uint TypeImage = 0x1000000;
        public const uint ProtX = 0x10;
        public const uint ProtRX = 0x20;
        public const uint ProtRWX = 0x40;
        public const uint ProtXwc = 0x80;

        // Legacy aliases used by call sites
        public const uint PROCESS_QUERY_INFORMATION = AccessQuery;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = AccessQueryLimited;
        public const uint PROCESS_VM_READ = AccessVmRead;
        public const uint MEM_COMMIT = StateCommit;
        public const uint MEM_IMAGE = TypeImage;
        public const uint PAGE_EXECUTE = ProtX;
        public const uint PAGE_EXECUTE_READ = ProtRX;
        public const uint PAGE_EXECUTE_READWRITE = ProtRWX;
        public const uint PAGE_EXECUTE_WRITECOPY = ProtXwc;

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        // CloseHandle stays here; process-inspection APIs go through NativeResolver
        // (plain [DllImport] - no GetProcAddress hiding; see NativeResolver remarks).

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        public static bool CanInspect(int pid, string? imagePath = null)
        {
            if (pid <= 4) return false;
            // Name-first: Denuvo titles self-terminate on VM_READ even when path resolve races.
            if (SecurityValidation.IsGameOrAntiCheatProcess(pid, imagePath))
                return false;
            imagePath ??= SecurityValidation.GetProcessImagePath(pid);
            // Fail closed: unresolved path -> no VM_READ (PPL / anti-cheat / startup race).
            // Prefer missing a scan over killing interactive games.
            if (string.IsNullOrEmpty(imagePath))
                return false;
            return !SecurityValidation.IsGameOrAntiCheatPath(imagePath);
        }

        public static IntPtr OpenRemoteHandle(uint access, int pid)
        {
            // Central gate: never grant VM_READ to game / unresolved PIDs.
            if ((access & AccessVmRead) != 0 && !CanInspect(pid))
                return IntPtr.Zero;
            return NativeResolver.OpenProcess(access, false, pid);
        }

        public static bool CopyRemote(IntPtr hProcess, IntPtr address, byte[] buffer, out int bytesRead)
        {
            bytesRead = 0;
            if (hProcess == IntPtr.Zero) return false;
            return NativeResolver.ReadProcessMemory(hProcess, address, buffer, buffer.Length, out bytesRead);
        }

        public static int QueryRemoteRegion(IntPtr hProcess, IntPtr address, out MEMORY_BASIC_INFORMATION mbi)
        {
            mbi = default;
            if (hProcess == IntPtr.Zero) return 0;
            return NativeResolver.VirtualQueryEx(hProcess, address, out mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
        }

        public static bool IsExecutableProtection(uint protect) =>
            protect is ProtX or ProtRX or ProtRWX or ProtXwc;

        public static bool LooksLikeMzPe(int processId, IntPtr address)
        {
            if (!CanInspect(processId) || address == IntPtr.Zero) return false;
            var buf = new byte[2];
            IntPtr h = OpenRemoteHandle(AccessQuery | AccessVmRead, processId);
            if (h == IntPtr.Zero) return false;
            try
            {
                if (!CopyRemote(h, address, buf, out int n) || n < 2) return false;
                return buf[0] == (byte)'M' && buf[1] == (byte)'Z';
            }
            catch { return false; }
            finally { CloseHandle(h); }
        }

        public static int QuerySystemInfo(int infoClass, IntPtr buffer, int size, out int returnLength)
        {
            return NativeResolver.NtQuerySystemInformation(infoClass, buffer, size, out returnLength);
        }

        public static bool DupHandle(IntPtr srcProc, IntPtr src, IntPtr dstProc, out IntPtr dst, int access, bool inherit, int options)
        {
            return NativeResolver.DuplicateHandle(srcProc, src, dstProc, out dst, access, inherit, options);
        }

        /// <summary>
        /// Enumerates every mapped module (native + WOW64) of <paramref name="pid"/>.
        ///
        /// Process.Modules is backed by the Toolhelp/PSAPI default filter and, from a 64-bit
        /// host, silently returns an empty or partial list for a 32-bit (WOW64) target - which
        /// hid injected 32-bit modules from the unload/quarantine engine. We now always run the
        /// PSAPI EnumProcessModulesEx(LIST_MODULES_ALL) path (native + WOW64 in one pass) and
        /// merge it with the managed list, deduped by module base address. Enumeration failures
        /// are logged rather than swallowed so coverage holes are visible.
        /// </summary>
        public static List<(string Name, string Path, IntPtr Base, int Size)> EnumModules(int pid)
        {
            var byBase = new Dictionary<IntPtr, (string Name, string Path, IntPtr Base, int Size)>();

            if (!CanInspect(pid))
            {
                MappedModuleCache.Replace(pid, new List<(string, string, IntPtr, int)>());
                return new List<(string, string, IntPtr, int)>();
            }

            // 1) Managed snapshot. Cheap and works for same-bitness targets. May throw or
            //    return a short list for cross-bitness targets - that is exactly the gap the
            //    native pass below closes.
            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(pid);
                foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
                {
                    var entry = (
                        mod.ModuleName ?? "",
                        mod.FileName ?? "",
                        mod.BaseAddress,
                        mod.ModuleMemorySize);
                    byBase[mod.BaseAddress] = entry;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[NativeProcessMemory] Process.Modules failed for PID {pid} (expected for cross-bitness targets; native pass follows): {ex.Message}");
            }

            // 2) Native LIST_MODULES_ALL pass. This is the authoritative enumeration and the
            //    only one that reliably sees 32-bit modules from a 64-bit host.
            EnumModulesNative(pid, byBase);

            var list = new List<(string, string, IntPtr, int)>(byBase.Count);
            foreach (var kv in byBase) list.Add(kv.Value);

            MappedModuleCache.Replace(pid, list);
            return list;
        }

        /// <summary>
        /// PSAPI EnumProcessModulesEx(LIST_MODULES_ALL). Merges into <paramref name="byBase"/>,
        /// keyed by module base address so it does not double-count entries the managed pass
        /// already found. Requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ.
        /// </summary>
        private static void EnumModulesNative(int pid,
            Dictionary<IntPtr, (string Name, string Path, IntPtr Base, int Size)> byBase)
        {
            IntPtr h = OpenRemoteHandle(AccessQuery | AccessVmRead, pid);
            if (h == IntPtr.Zero)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[NativeProcessMemory] EnumModulesNative: could not open PID {pid} for module enumeration (err {Marshal.GetLastWin32Error()}).");
                return;
            }

            try
            {
                // Size probe: first call reports the bytes needed for the full handle array.
                if (!NativeResolver.EnumProcessModulesEx(h, Array.Empty<IntPtr>(), 0,
                        out int needed, NativeResolver.LIST_MODULES_ALL) && needed <= 0)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"[NativeProcessMemory] EnumProcessModulesEx size probe failed for PID {pid} (err {Marshal.GetLastWin32Error()}).");
                    return;
                }

                if (needed <= 0) return;
                int count = needed / IntPtr.Size;
                // Loop until the array is large enough (module set can grow between calls).
                IntPtr[] handles = new IntPtr[count];
                if (!NativeResolver.EnumProcessModulesEx(h, handles, needed, out int needed2,
                        NativeResolver.LIST_MODULES_ALL))
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"[NativeProcessMemory] EnumProcessModulesEx fill failed for PID {pid} (err {Marshal.GetLastWin32Error()}).");
                    return;
                }
                if (needed2 < needed) count = needed2 / IntPtr.Size;

                var nameSb = new System.Text.StringBuilder(260);
                var pathSb = new System.Text.StringBuilder(1024);

                for (int i = 0; i < count && i < handles.Length; i++)
                {
                    IntPtr hMod = handles[i];
                    if (hMod == IntPtr.Zero) continue;

                    IntPtr baseAddr = hMod; // module handle == base address in the target
                    if (byBase.ContainsKey(baseAddr)) continue; // managed pass already had it

                    string path = "";
                    pathSb.Clear();
                    int pn = NativeResolver.GetModuleFileNameExW(h, hMod, pathSb, pathSb.Capacity);
                    if (pn > 0) path = pathSb.ToString();

                    string name = "";
                    nameSb.Clear();
                    int nn = NativeResolver.GetModuleBaseNameW(h, hMod, nameSb, nameSb.Capacity);
                    if (nn > 0) name = nameSb.ToString();
                    else if (path.Length > 0) name = System.IO.Path.GetFileName(path);

                    int size = 0;
                    if (NativeResolver.GetModuleInformation(h, hMod,
                            out NativeResolver.MODULEINFO mi, Marshal.SizeOf<NativeResolver.MODULEINFO>()))
                    {
                        size = (int)Math.Min(mi.SizeOfImage, int.MaxValue);
                        baseAddr = mi.lpBaseOfDll != IntPtr.Zero ? mi.lpBaseOfDll : hMod;
                    }

                    if (byBase.ContainsKey(baseAddr)) continue;
                    byBase[baseAddr] = (name, path, baseAddr, size);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[NativeProcessMemory] EnumModulesNative failed for PID {pid}: {ex.Message}");
            }
            finally
            {
                CloseHandle(h);
            }
        }
    }

    /// <summary>
    /// Image ranges from the one-shot EnumModules baseline + ETW ImageLoad.
    /// EtwThreatIntelMonitor must not EnumModules every 5s.
    /// </summary>
    internal static class MappedModuleCache
    {
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<int, List<(ulong Base, ulong End)>> Ranges = new();

        public static void Replace(int pid, List<(string Name, string Path, IntPtr Base, int Size)> modules)
        {
            var list = new List<(ulong, ulong)>(modules.Count);
            foreach (var m in modules)
            {
                if (m.Base == IntPtr.Zero) continue;
                ulong b = (ulong)m.Base;
                list.Add((b, b + (ulong)Math.Max(m.Size, 1)));
            }
            Ranges[pid] = list;
        }

        public static void Add(int pid, ulong imageBase, ulong imageSize)
        {
            if (imageBase == 0) return;
            var list = Ranges.GetOrAdd(pid, _ => new List<(ulong, ulong)>());
            lock (list)
                list.Add((imageBase, imageBase + Math.Max(imageSize, 1UL)));
        }

        public static List<(ulong Base, ulong End)> Get(int pid)
        {
            if (!Ranges.TryGetValue(pid, out var list) || list == null)
                return new List<(ulong, ulong)>();
            lock (list)
                return new List<(ulong, ulong)>(list);
        }

        /// <summary>Evict a PID on ProcessStop so dead entries don't accumulate.</summary>
        public static void Remove(int pid) => Ranges.TryRemove(pid, out _);
    }
}
