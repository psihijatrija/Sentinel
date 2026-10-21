using System;
using System.IO;

namespace NanoAV
{
    // Compiled unchanged into NanoAV and its unit tests. No scanner/EXE load needed.
    internal static class SentinelCoexistencePaths
    {
        internal static bool IsInside(string candidate, string directory)
        {
            if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(directory)
                || !Path.IsPathRooted(candidate) || !Path.IsPathRooted(directory)) return false;
            string root = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string full = Path.GetFullPath(candidate);
            return full.Equals(root, StringComparison.OrdinalIgnoreCase)
                || full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }

        internal static bool IsProtectedResolvedPath(string path, string installDirectory, string dataDirectory)
        {
            return IsInside(path, installDirectory) || IsInside(path, dataDirectory);
        }
    }
}
