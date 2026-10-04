// Sentinel.AutoRotate - P/Invoke declarations.
//
// All signatures are synchronous. No async anywhere in this tool.
// APIs:
//   netapi32.dll  : NetUserSetInfo (level 1003 / USER_INFO_1003)
//   advapi32.dll  : LsaOpenPolicy / LsaStorePrivateData / LsaClose / LsaNtStatusToWinError
//   kernel32.dll  : WTSGetActiveConsoleSessionId
//   wtsapi32.dll  : WTSQuerySessionInformation (WTS_INFO_CLASS.WTSUserName=5) / WTSFreeMemory

using System.Runtime.InteropServices;

namespace Sentinel.AutoRotate;

internal static class NativeMethods
{
    // ---- netapi32: NetUserSetInfo -------------------------------------------------

    // USER_INFO_1003: single-field struct used to set a local account's password.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct USER_INFO_1003
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri1003_password;
    }

    // servername NULL => local machine. level 1003 => password only.
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    internal static extern uint NetUserSetInfo(
        [MarshalAs(UnmanagedType.LPWStr)] string? servername,
        [MarshalAs(UnmanagedType.LPWStr)] string username,
        uint level,
        ref USER_INFO_1003 buf,
        out uint parm_err);

    internal const uint NERR_Success = 0;

    // ---- advapi32: LSA private data ----------------------------------------------

    [StructLayout(LayoutKind.Sequential)]
    internal struct LSA_UNICODE_STRING
    {
        public ushort Length;        // bytes, not including null terminator
        public ushort MaximumLength; // bytes
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    internal const uint POLICY_CREATE_SECRET = 0x00000020;

    [DllImport("advapi32.dll", SetLastError = false)]
    internal static extern uint LsaOpenPolicy(
        IntPtr SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        uint DesiredAccess,
        out IntPtr PolicyHandle);

    // Pass PrivateData == null (IntPtr.Zero) to delete the secret.
    [DllImport("advapi32.dll", SetLastError = false)]
    internal static extern uint LsaStorePrivateData(
        IntPtr PolicyHandle,
        ref LSA_UNICODE_STRING KeyName,
        IntPtr PrivateData);

    [DllImport("advapi32.dll", SetLastError = false)]
    internal static extern uint LsaClose(IntPtr PolicyHandle);

    [DllImport("advapi32.dll", SetLastError = false)]
    internal static extern int LsaNtStatusToWinError(uint Status);

    // ---- kernel32 / wtsapi32: active console session -----------------------------

    [DllImport("kernel32.dll")]
    internal static extern uint WTSGetActiveConsoleSessionId();

    internal const int WTS_CURRENT_SERVER_HANDLE = 0;

    internal enum WTS_INFO_CLASS
    {
        WTSUserName = 5,
    }

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WTSQuerySessionInformation(
        IntPtr hServer,
        uint sessionId,
        WTS_INFO_CLASS wtsInfoClass,
        out IntPtr ppBuffer,
        out uint pBytesReturned);

    [DllImport("wtsapi32.dll")]
    internal static extern void WTSFreeMemory(IntPtr pMemory);
}
