using System;
using System.IO;
using System.Linq;

namespace Sentinel.Core
{
    // Path classification only: a standard location does not establish signature trust.
    internal static class DriverPathPolicy
    {
        internal static string Resolve(string imagePath, string windowsDirectory)
        {
            string path = imagePath.Trim().Trim('"').Replace('/', '\\');
            if (path.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase)) path = path.Substring(4);
            if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                path = windowsDirectory.TrimEnd('\\') + path.Substring(11);
            else if (path.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase))
                path = windowsDirectory.TrimEnd('\\') + @"\" + path;
            else if (path.IndexOf('\\') < 0 && path.IndexOf(':') < 0)
                path = windowsDirectory.TrimEnd('\\') + @"\System32\drivers\" + path;
            // Canonicalize traversal before testing containment; unsupported device paths stay unknown.
            if (path.Length > 2 && path[1] == ':' && path[2] == '\\')
            {
                var segments = new System.Collections.Generic.List<string>();
                foreach (var segment in path.Substring(3).Split('\\'))
                {
                    if (segment.Length == 0 || segment == ".") continue;
                    if (segment == "..")
                    {
                        if (segments.Count == 0) return "";
                        segments.RemoveAt(segments.Count - 1);
                    }
                    else segments.Add(segment);
                }
                path = path.Substring(0, 3) + string.Join(@"\", segments);
            }
            return path;
        }

        internal static bool IsStandard(string path, string windowsDirectory)
        {
            if (string.IsNullOrEmpty(path) || path.Contains("..")) return false;
            string root = windowsDirectory.TrimEnd('\\');
            return new[] { root + @"\System32\drivers\", root + @"\System32\DriverStore\", root + @"\SysWOW64\drivers\" }
                .Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        }
    }
}
