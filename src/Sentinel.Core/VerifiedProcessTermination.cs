using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Sentinel.Core
{
    /// <summary>One process handle supplies identity, policy checks, termination and exit verification.
    /// This verifies the selected process only, not descendants or other response effects.</summary>
    internal static class VerifiedProcessTermination
    {
        private const uint QueryLimitedInformation = 0x1000;
        private const uint Terminate = 0x0001;
        private const uint Synchronize = 0x00100000;

        internal static bool TryTerminate(int pid, DateTime evidenceUtc, out string reason, string? expectedImagePath = null, DateTime? expectedStartUtc = null, Func<string, bool>? requiredImagePolicy = null)
        {
            reason = "Process termination refused";
            if (pid <= 4 || pid == System.Net48Environment.ProcessId) return false;
            try
            {
                using var handle = new SafeProcessHandle(
                    NativeResolver.OpenProcess(QueryLimitedInformation | Terminate | Synchronize, false, pid), ownsHandle: true);
                if (handle.IsInvalid) { reason = "Cannot open target process with required rights"; return false; }
                using var target = new NativeTarget(handle);
                return ProcessTerminationPolicy.TryTerminate(target, evidenceUtc, DateTime.UtcNow,
                    image => HardeningModule.IsProtectedResponseImage(image) ||
                        (requiredImagePolicy != null && !requiredImagePolicy(image)),
                    out reason, expectedImagePath, expectedStartUtc);
            }
            catch (Exception ex)
            {
                reason = "Process termination unavailable: " + ex.GetType().Name;
                return false;
            }
        }

        private sealed class NativeTarget : IProcessTerminationTarget
        {
            private readonly SafeProcessHandle _handle;
            internal NativeTarget(SafeProcessHandle handle) => _handle = handle;
            public DateTime CreatedUtc => GetProcessTimes(_handle, out var created, out _, out _, out _)
                ? DateTime.FromFileTimeUtc(created) : throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            public bool IsCritical => IsProcessCritical(_handle, out var critical)
                ? critical : throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            public string ImagePath
            {
                get
                {
                    var image = new StringBuilder(32768);
                    int size = image.Capacity;
                    if (!QueryFullProcessImageName(_handle, 0, image, ref size))
                        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                    return image.ToString();
                }
            }
            public bool Terminate() => TerminateProcess(_handle, 1);
            public bool WaitForExit(int milliseconds) => WaitForSingleObject(_handle, (uint)milliseconds) == 0;
            // The outer scope owns and closes the native SafeProcessHandle.
            public void Dispose() { }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(SafeProcessHandle process, out long created, out long exited, out long kernel, out long user);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsProcessCritical(SafeProcessHandle process, [MarshalAs(UnmanagedType.Bool)] out bool critical);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder image, ref int size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);
    }
}
