using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;

namespace Sentinel.Core
{
    internal sealed class RunValueSnapshot
    {
        internal object Value { get; set; } = "";
        internal RegistryValueKind Kind { get; set; }
    }

    internal interface IRunValueStore
    {
        RunValueSnapshot? Read(string name);
        void Delete(string name);
    }

    internal sealed class RegistryRunValueStore : IRunValueStore
    {
        private readonly RegistryKey _key;
        internal RegistryRunValueStore(RegistryKey key) => _key = key;
        public RunValueSnapshot? Read(string name)
        {
            if (!_key.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase)) return null;
            var kind = _key.GetValueKind(name);
            var value = _key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            return value == null ? null : new RunValueSnapshot { Kind = kind, Value = value };
        }
        public void Delete(string name) => _key.DeleteValue(name, false);
    }

    internal static class RunKeyCleanup
    {
        internal static IReadOnlyCollection<string> ConfirmedTargets(ChainTraceResult result) => result.QuarantinedFiles
            .Where(file => result.AdditionalEffects.Any(effect => effect.Action == "Quarantine" &&
                effect.Status == ResponseExecutionStatus.Verified &&
                string.Equals(effect.Target, file.OriginalPath, StringComparison.OrdinalIgnoreCase)))
            .Select(file => file.OriginalPath).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        internal static string? DirectExecutable(string? command)
        {
            if (string.IsNullOrWhiteSpace(command) || command!.Length > 32768 || command.Any(char.IsControl)) return null;
            command = command.Trim();
            string executable;
            if (command[0] == '"')
            {
                int end = command.IndexOf('"', 1);
                if (end < 0 || (end + 1 < command.Length && !char.IsWhiteSpace(command[end + 1]))) return null;
                executable = command.Substring(1, end - 1);
            }
            else
            {
                int end = command.IndexOfAny(new[] { ' ', '\t' });
                executable = end < 0 ? command : command.Substring(0, end);
            }
            return NormalizeExecutable(executable);
        }

        private static string? NormalizeExecutable(string path)
        {
            path = path.Replace('/', '\\');
            if (path.Length < 7 || !char.IsLetter(path[0]) || path[1] != ':' || path[2] != '\\' ||
                path.IndexOfAny(new[] { '%', '"', '*', '?', '<', '>', '|' }) >= 0 || path.IndexOf(':', 2) >= 0 ||
                !(path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".com", StringComparison.OrdinalIgnoreCase))) return null;
            var pieces = new List<string>();
            foreach (var part in path.Substring(3).Split('\\'))
            {
                if (part == "" || part == "." || part == "..") return null;
                if (part.EndsWith(" ", StringComparison.Ordinal) || part.EndsWith(".", StringComparison.Ordinal)) return null;
                pieces.Add(part);
            }
            return char.ToUpperInvariant(path[0]) + @":\" + string.Join(@"\", pieces);
        }

        internal static bool Matches(RunValueSnapshot snapshot, IReadOnlyCollection<string> confirmedPaths)
        {
            if (snapshot.Value is not string command ||
                (snapshot.Kind != RegistryValueKind.String && snapshot.Kind != RegistryValueKind.ExpandString)) return false;
            var executable = DirectExecutable(command);
            return executable != null && confirmedPaths.Any(path =>
                string.Equals(executable, NormalizeExecutable(path), StringComparison.OrdinalIgnoreCase));
        }

        internal static ResponseEffect Remove(IRunValueStore store, string name, RunValueSnapshot expected,
            IReadOnlyCollection<string> confirmedPaths, string target)
        {
            var effect = new ResponseEffect { Action = "RegistryRemoval", Target = target, Status = ResponseExecutionStatus.Refused };
            if (!Matches(expected, confirmedPaths)) { effect.Detail = "No exact direct launch of a verified quarantined payload."; return effect; }
            var current = store.Read(name);
            if (current == null) { effect.Status = ResponseExecutionStatus.Verified; effect.Detail = "Attributed Run value already absent."; return effect; }
            if (current.Kind != expected.Kind || current.Value is not string text ||
                !string.Equals(text, expected.Value as string, StringComparison.Ordinal))
            { effect.Detail = "Run value changed since attribution; no deletion attempted."; return effect; }
            store.Delete(name);
            bool absent = store.Read(name) == null;
            effect.Status = absent ? ResponseExecutionStatus.Verified : ResponseExecutionStatus.Failed;
            effect.Detail = absent ? "Exact attributed Run value absent on read-back." : "Run value remains or was recreated; cleanup is not verified.";
            return effect;
        }
    }
}
