using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Sentinel.Core
{
    /// <summary>The interactive Agent must never inherit SYSTEM or an elevated administrator token.</summary>
    public static class UserSessionPrivilege
    {
        public static bool IsUnprivileged(WindowsIdentity identity) =>
            !identity.IsSystem && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);

        public static bool IsCurrentProcessUnprivileged()
        {
            using var identity = WindowsIdentity.GetCurrent();
            return IsUnprivileged(identity);
        }

        // Takes ownership of the supplied WTS token only when replacing it with its limited linked token.
        public static void RequireLimitedToken(ref IntPtr token)
        {
            using (var identity = new WindowsIdentity(token))
                if (IsUnprivileged(identity)) return;
            if (!GetTokenInformation(token, 19 /* TokenLinkedToken */, out var linked, IntPtr.Size, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "No limited user token is available for Sentinel Agent");
            try
            {
                using var identity = new WindowsIdentity(linked);
                if (!IsUnprivileged(identity))
                    throw new InvalidOperationException("Refusing to launch Sentinel Agent with a privileged token");
                CloseHandle(token);
                token = linked;
                linked = IntPtr.Zero;
            }
            finally { if (linked != IntPtr.Zero) CloseHandle(linked); }
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(IntPtr token, int informationClass,
            out IntPtr information, int informationLength, out int returnLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);
    }
}
