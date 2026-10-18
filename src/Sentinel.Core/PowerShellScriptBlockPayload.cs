using System;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    internal static class PowerShellScriptBlockPayload
    {
        // Individual fragments are evaluated separately. No cross-process or cross-script
        // concatenation and no claimed reconstruction when an ETW fragment is missing.
        internal static string Read(EtwRawEvent evt)
        {
            if (evt.EventId != 4104 || evt.Version != 1 || evt.UserData == IntPtr.Zero ||
                evt.UserDataLength < 14 || (evt.UserDataLength & 1) != 0) return "";
            int number = Marshal.ReadInt32(evt.UserData, 0);
            int total = Marshal.ReadInt32(evt.UserData, 4);
            if (number < 1 || total < number || total > 4096) return "";
            int chars = (evt.UserDataLength - 8) / 2;
            string payload = Marshal.PtrToStringUni(IntPtr.Add(evt.UserData, 8), chars) ?? "";
            int end = payload.IndexOf('\0');
            if (end < 0) return "";
            return payload.Substring(0, end);
        }
    }
}
