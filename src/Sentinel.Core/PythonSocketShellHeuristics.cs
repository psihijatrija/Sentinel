using System;
using System.Text.RegularExpressions;

namespace Sentinel.Core
{
    // Deliberately narrow: inline Python, one connected socket, and all three
    // shell streams bound to that socket. No verdict from Python/Ren'Py names alone.
    internal static class PythonSocketShellHeuristics
    {
        internal static bool IsSocketShell(string? processName, string? command)
        {
            if (string.IsNullOrEmpty(command) || command!.Length > 65536) return false;
            var name = (processName ?? "").ToLowerInvariant();
            if (!(name == "python" || name == "python.exe" || name == "pythonw.exe" || name == "pythonw" || name == "py" ||
                  name == "python3" || name == "python3.exe" || name == "py.exe")) return false;
            try
            {
                var timeout = TimeSpan.FromMilliseconds(50);
                // Match executable statements, rather than strings printed by a game.
                var inline = Regex.Match(command, @"(?:^|\s)-c\s+""(?<code>[^""\r\n]+)""\s*$", RegexOptions.CultureInvariant, timeout);
                if (!inline.Success) return false;
                string code = inline.Groups["code"].Value;
                var socket = Regex.Match(code, @"(?:^|;)\s*(?<s>[A-Za-z_]\w*)\s*=\s*socket\.socket\([^;]*\)\s*;", RegexOptions.CultureInvariant, timeout);
                if (!socket.Success) return false;
                string variable = Regex.Escape(socket.Groups["s"].Value);
                string rest = code.Substring(socket.Index + socket.Length);
                if (!Regex.IsMatch(rest, @"(?:^|;)\s*" + variable + @"\.connect\([^;]+\)\s*;", RegexOptions.CultureInvariant, timeout)) return false;
                string stream = variable + @"\.fileno\(\)";
                return Regex.IsMatch(rest,
                    @"(?:^|;)\s*subprocess\.(?:call|Popen|run)\(\s*\[\s*'(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|/bin/(?:ba)?sh)'\s*\]\s*,\s*stdin\s*=\s*" + stream +
                    @"\s*,\s*stdout\s*=\s*" + stream + @"\s*,\s*stderr\s*=\s*" + stream + @"\s*\)\s*;?\s*$",
                    RegexOptions.CultureInvariant, timeout);
            }
            catch (RegexMatchTimeoutException) { return false; }
        }
    }
}
