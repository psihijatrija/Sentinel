using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using Xunit;
using Sentinel.Core;


namespace Sentinel.Tests
{
    public class NativeResolverCompletenessTests
    {
        private static readonly HashSet<string> InspectionApis = new(StringComparer.Ordinal)
        {
            "OpenProcess",
            "ReadProcessMemory",
            "VirtualQueryEx",
            "DuplicateHandle",
            "NtQuerySystemInformation",
            "NtQueryObject",
            "NtQueryInformationProcess",
        };

        [Fact]
        public void InspectionApis_HaveNoStaticDllImport_OutsideNativeResolver()
        {
            var leftovers = new List<string>();
            var asm = typeof(NativeResolver).Assembly;
            foreach (var type in asm.GetTypes())
            {
                if (type == typeof(NativeResolver))
                    continue;

                foreach (var method in type.GetMethods(
                    BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                {
                    var dll = method.GetCustomAttribute<DllImportAttribute>();
                    if (dll == null)
                        continue;
                    var entry = string.IsNullOrEmpty(dll.EntryPoint) ? method.Name : dll.EntryPoint;
                    if (InspectionApis.Contains(entry))
                        leftovers.Add($"{type.FullName}.{method.Name} -> {dll.Value}!{entry}");
                }
            }

            Assert.True(leftovers.Count == 0,
                "Static DllImport of inspection APIs remains outside NativeResolver:\n" +
                string.Join("\n", leftovers));
        }

        [Fact]
        public void OpenProcess_WorksForCurrentProcess()
        {
            // v2.3.8 AV FP policy: NativeResolver uses plain [DllImport], not GetProcAddress.
            int pid = Process.GetCurrentProcess().Id;
            IntPtr h = NativeResolver.OpenProcess(
                NativeProcessMemory.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            Assert.NotEqual(IntPtr.Zero, h);
            Assert.True(NativeProcessMemory.CloseHandle(h));
        }

        [Fact]
        public void NativeResolver_DoesNotUseGetProcAddressBootstrap()
        {
            // v2.3.8 AV FP: inspection APIs are plain [DllImport], not GetProcAddress-resolved.
            var methods = typeof(NativeResolver).GetMethods(
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.DeclaredOnly);
            Assert.DoesNotContain(methods, m =>
            {
                var dll = m.GetCustomAttribute<DllImportAttribute>();
                if (dll == null) return false;
                var entry = string.IsNullOrEmpty(dll.EntryPoint) ? m.Name : dll.EntryPoint;
                return entry.Equals("GetProcAddress", StringComparison.Ordinal)
                    || entry.Equals("GetModuleHandleW", StringComparison.Ordinal);
            });
            Assert.Contains(methods, m =>
                m.GetCustomAttribute<DllImportAttribute>() != null
                && (string.IsNullOrEmpty(m.GetCustomAttribute<DllImportAttribute>()!.EntryPoint)
                    ? m.Name
                    : m.GetCustomAttribute<DllImportAttribute>()!.EntryPoint) == "OpenProcess");
        }

        [Fact]
        public void NativeResolver_ExposesAllSevenInspectionForwards()
        {
            var names = typeof(NativeResolver)
                .GetMethods(BindingFlags.Public | BindingFlags.Static)
                .Select(m => m.Name)
                .ToHashSet(StringComparer.Ordinal);
            foreach (var api in InspectionApis)
                Assert.Contains(api, names);
        }
    }
}
