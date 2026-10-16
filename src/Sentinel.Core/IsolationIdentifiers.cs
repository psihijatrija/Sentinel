using System;

namespace Sentinel.Core
{
    internal static class IsolationIdentifiers
    {
        internal static bool IsContainerReference(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length > 128 || !IsAsciiAlphanumeric(value[0])) return false;
            foreach (var c in value)
                if (!IsAsciiAlphanumeric(c) && c != '_' && c != '.' && c != '-') return false;
            return true;
        }
        // Restricts an already-authorized VM response; a filename never supplies kill authority.
        // Shared management hosts such as vmms must never be treated as one VM's worker.
        internal static bool IsDedicatedVmHostImage(string image)
        {
            var name = System.IO.Path.GetFileNameWithoutExtension(image);
            return string.Equals(name, "vmwp", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(name, "vmware-vmx", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(name, "VirtualBoxVM", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(name, "VBoxHeadless", StringComparison.OrdinalIgnoreCase);
        }
        internal static bool IsContainerId(string value) => IsHex(value, 64);
        internal static bool IsImageId(string value) => value != null && value.StartsWith("sha256:", StringComparison.Ordinal) && IsHex(value.Substring(7), 64);
        private static bool IsHex(string value, int length)
        {
            if (value == null || value.Length != length) return false;
            foreach (var c in value)
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
            return true;
        }
        private static bool IsAsciiAlphanumeric(char c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    }
}
