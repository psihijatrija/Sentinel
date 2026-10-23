using System;
using System.Runtime.InteropServices;
using System.Threading;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public sealed class LoaderWindowsFactAttribute : FactAttribute
    {
        public LoaderWindowsFactAttribute()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) Skip = "Requires native Windows memory APIs.";
        }
    }

    public class LoaderPayloadWindowsTests
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocation, uint protection);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr address, UIntPtr size, uint protection, out uint oldProtection);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFree(IntPtr address, UIntPtr size, uint freeType);

        [LoaderWindowsFact]
        public void NativeReadonlyHeaderAndRxSectionAreDetectedWithoutExecutingOrInjectingCode()
        {
            var allocation = VirtualAlloc(IntPtr.Zero, new UIntPtr(8192), 0x3000, 0x04);
            Assert.NotEqual(IntPtr.Zero, allocation);
            try
            {
                byte[] header = LoaderPayloadCoverageTests.Header();
                Marshal.Copy(header, 0, allocation, header.Length);
                Assert.True(VirtualProtect(allocation, new UIntPtr(4096), 0x02, out _));
                Assert.True(VirtualProtect(IntPtr.Add(allocation, 4096), new UIntPtr(4096), 0x20, out _));
                ulong start = unchecked((ulong)allocation.ToInt64());
                IntPtr self = new IntPtr(-1); // current-process pseudo-handle
                var payloads = UnbackedPeScanner.Scan(address =>
                {
                    if (address < start || address - start >= 8192) return null;
                    return NativeProcessMemory.QueryRemoteRegion(self, new IntPtr(unchecked((long)address)), out var region) == 0
                        ? (NativeProcessMemory.MEMORY_BASIC_INFORMATION?)null : region;
                }, address =>
                {
                    var bytes = new byte[4096];
                    return NativeProcessMemory.CopyRemote(self, new IntPtr(unchecked((long)address)), bytes, out int count) && count == bytes.Length
                        ? bytes : null;
                }, CancellationToken.None, start);
                var payload = Assert.Single(payloads);
                Assert.Equal(start, payload.Allocation);
                Assert.Equal(start + 4096, payload.ExecutablePage);
            }
            finally { Assert.True(VirtualFree(allocation, UIntPtr.Zero, 0x8000)); }
        }

        [LoaderWindowsFact]
        public void CleanQtAndRuntimeDllNamesRemainAllowedBesideTheirApplication()
        {
            foreach (var name in new[] { "Qt5Core.dll", "Qt5Gui.dll", "Qt5Widgets.dll", "vcruntime140.dll" })
            {
                var verdict = ModuleIdentity.Evaluate(@"C:\Users\Test\Downloads\VisualNovel\game.exe",
                    @"C:\Users\Test\Downloads\VisualNovel\" + name, _ => false);
                Assert.True(verdict.Allowed, verdict.Reason);
            }
        }
    }
}
